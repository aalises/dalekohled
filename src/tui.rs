use crate::{Report, SessionMeta, Source};
use anyhow::Result;
use crossterm::event::{self, Event as CEvent, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, List, ListItem, ListState, Paragraph},
    DefaultTerminal, Frame,
};

pub(crate) fn pick(semantic_on: bool) -> Result<()> {
    let sessions = crate::sessions();
    if sessions.is_empty() {
        anyhow::bail!("no sessions found under ~/.pi, ~/.claude or ~/.codex");
    }
    let mut terminal = ratatui::init();
    let res = App::new(sessions, semantic_on).run(&mut terminal);
    ratatui::restore();
    res
}

struct App {
    sessions: Vec<SessionMeta>,
    filtered: Vec<usize>,
    query: String,
    picker: ListState,
    semantic_on: bool,
    pane: Option<Pane>,
    flash: Option<String>,
}

/// A scrollable results view (session report or estate audit).
struct Pane {
    block_title: &'static str,
    header: Vec<Line<'static>>,
    lines: Vec<Line<'static>>,
    /// Parallel to `lines`: the concrete fix shown when Enter is pressed on a row.
    fixes: Vec<Option<String>>,
    list: ListState,
    export_name: String,
    export_md: String,
}

impl App {
    fn new(sessions: Vec<SessionMeta>, semantic_on: bool) -> Self {
        let filtered = (0..sessions.len()).collect();
        let mut picker = ListState::default();
        picker.select(Some(0));
        App { sessions, filtered, query: String::new(), picker, semantic_on, pane: None, flash: None }
    }

    fn run(mut self, t: &mut DefaultTerminal) -> Result<()> {
        loop {
            if self.pane.is_none() {
                self.fill_previews(t.size()?.height as usize);
            }
            t.draw(|f| self.draw(f))?;
            let CEvent::Key(k) = event::read()? else { continue };
            if k.kind != KeyEventKind::Press {
                continue;
            }
            if k.modifiers.contains(KeyModifiers::CONTROL) {
                match k.code {
                    KeyCode::Char('c') => return Ok(()),
                    KeyCode::Char('e') if self.pane.is_none() => {
                        self.open_estate(t);
                        continue;
                    }
                    _ => {}
                }
            }
            let quit = if self.pane.is_some() { self.pane_key(k.code) } else { self.picker_key(k.code, t) };
            if quit {
                return Ok(());
            }
        }
    }

    fn fill_previews(&mut self, height: usize) {
        let start = self.picker.offset().saturating_sub(5);
        for &si in self.filtered.iter().skip(start).take(height + 10) {
            let s = &mut self.sessions[si];
            if s.preview.is_none() {
                s.preview = Some(crate::preview(s.source, &s.path));
            }
        }
    }

    // ----- picker -----

    fn picker_key(&mut self, code: KeyCode, t: &mut DefaultTerminal) -> bool {
        self.flash = None;
        match code {
            KeyCode::Up => self.move_sel(-1),
            KeyCode::Down => self.move_sel(1),
            KeyCode::PageUp => self.move_sel(-15),
            KeyCode::PageDown => self.move_sel(15),
            KeyCode::Tab => self.semantic_on = !self.semantic_on,
            KeyCode::Enter => self.open_selected(t),
            KeyCode::Backspace => {
                self.query.pop();
                self.refilter();
            }
            KeyCode::Esc => {
                if self.query.is_empty() {
                    return true;
                }
                self.query.clear();
                self.refilter();
            }
            KeyCode::Char(c) => {
                self.query.push(c);
                self.refilter();
            }
            _ => {}
        }
        false
    }

    fn move_sel(&mut self, d: isize) {
        if self.filtered.is_empty() {
            return;
        }
        let cur = self.picker.selected().unwrap_or(0) as isize;
        let next = (cur + d).clamp(0, self.filtered.len() as isize - 1);
        self.picker.select(Some(next as usize));
    }

    fn refilter(&mut self) {
        let q = self.query.to_lowercase();
        self.filtered = self
            .sessions
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                q.is_empty()
                    || s.source.label().contains(&q)
                    || s.title.to_lowercase().contains(&q)
                    || s.preview.as_deref().unwrap_or("").to_lowercase().contains(&q)
            })
            .map(|(i, _)| i)
            .collect();
        self.picker.select(if self.filtered.is_empty() { None } else { Some(0) });
        *self.picker.offset_mut() = 0;
    }

    fn busy_frame(t: &mut DefaultTerminal, msg: String) {
        let _ = t.draw(|f| {
            f.render_widget(Paragraph::new(format!("\n  {msg}")).block(Block::bordered().title(" cxwatch ")), f.area());
        });
    }

    fn open_selected(&mut self, t: &mut DefaultTerminal) {
        let Some(sel) = self.picker.selected() else { return };
        let Some(&si) = self.filtered.get(sel) else { return };
        let meta = self.sessions[si].clone();
        let note = if self.semantic_on { " + semantic LLM pass (may take a minute)" } else { "" };
        Self::busy_frame(t, format!("analyzing {} …{note}", meta.title));
        match crate::parse(&meta.path) {
            Err(e) => self.flash = Some(format!("cannot parse {}: {e}", meta.path.display())),
            Ok(events) => {
                let sem = self.semantic_on.then(|| {
                    crate::semantic(&events).unwrap_or_else(|e| crate::Semantic {
                        contradiction: format!("semantic unavailable: {e}"),
                        bloating: String::new(),
                        model_used: crate::SEMANTIC_MODEL.into(),
                    })
                });
                let report = crate::build_report(meta.path.display().to_string(), &events, sem);
                let stem = meta.path.file_stem().and_then(|s| s.to_str()).unwrap_or("session").to_string();
                self.pane = Some(Pane {
                    block_title: " report ",
                    header: report_header(&meta, &report),
                    lines: report_lines(&report),
                    fixes: Vec::new(),
                    list: selected_zero(),
                    export_name: format!("cxwatch-{stem}.md"),
                    export_md: crate::markdown(&report),
                });
            }
        }
    }

    fn open_estate(&mut self, t: &mut DefaultTerminal) {
        self.flash = None;
        Self::busy_frame(t, "auditing static context (scans all transcripts — can take a few seconds) …".into());
        let mut report = crate::estate::audit();
        if self.semantic_on {
            Self::busy_frame(t, "running semantic contradiction/duplication pass (may take a minute) …".into());
            report.semantic = Some(crate::estate::semantic_pass(&report).unwrap_or_else(|e| crate::Semantic {
                contradiction: format!("semantic unavailable: {e}"),
                bloating: String::new(),
                model_used: crate::SEMANTIC_MODEL.into(),
            }));
        }
        let (lines, fixes) = estate_lines(&report);
        self.pane = Some(Pane {
            block_title: " estate ",
            header: estate_header(&report),
            lines,
            fixes,
            list: selected_zero(),
            export_name: "cxwatch-estate.md".into(),
            export_md: crate::estate::markdown(&report),
        });
    }

    // ----- pane (report / estate) -----

    fn pane_key(&mut self, code: KeyCode) -> bool {
        self.flash = None;
        let pane = self.pane.as_mut().expect("pane");
        let max = pane.lines.len().saturating_sub(1) as isize;
        fn scroll(list: &mut ListState, d: isize, max: isize) {
            let cur = list.selected().unwrap_or(0) as isize;
            list.select(Some((cur + d).clamp(0, max) as usize));
        }
        match code {
            KeyCode::Up => scroll(&mut pane.list, -1, max),
            KeyCode::Down => scroll(&mut pane.list, 1, max),
            KeyCode::PageUp => scroll(&mut pane.list, -15, max),
            KeyCode::PageDown => scroll(&mut pane.list, 15, max),
            KeyCode::Enter => {
                if let Some(Some(fix)) = pane.fixes.get(pane.list.selected().unwrap_or(0)) {
                    self.flash = Some(format!("fix → {fix}"));
                }
            }
            KeyCode::Char('e') => {
                self.flash = Some(match std::fs::write(&pane.export_name, &pane.export_md) {
                    Ok(_) => format!("wrote {}", pane.export_name),
                    Err(e) => format!("export failed: {e}"),
                });
            }
            KeyCode::Esc | KeyCode::Backspace => self.pane = None,
            KeyCode::Char('q') => return true,
            _ => {}
        }
        false
    }

    // ----- drawing -----

    fn draw(&mut self, f: &mut Frame) {
        if self.pane.is_some() {
            self.draw_pane(f);
        } else {
            self.draw_picker(f);
        }
    }

    fn draw_picker(&mut self, f: &mut Frame) {
        let [list_area, status_area, keys_area] =
            Layout::vertical([Constraint::Min(1), Constraint::Length(1), Constraint::Length(1)]).areas(f.area());
        let w = list_area.width.saturating_sub(3) as usize;

        let items: Vec<ListItem> = self
            .filtered
            .iter()
            .map(|&si| {
                let s = &self.sessions[si];
                let title = crate::clip(&s.title, 38);
                let preview_w = w.saturating_sub(7 + 5 + 8 + 40);
                let preview = crate::clip(s.preview.as_deref().unwrap_or(""), preview_w);
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("{:<7}", s.source.label()),
                        Style::new().fg(source_color(s.source)).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(format!("{:>4} ", crate::ago(s.modified)), Style::new().fg(Color::DarkGray)),
                    Span::styled(format!("{:>6}  ", crate::size_fmt(s.size)), Style::new().fg(Color::DarkGray)),
                    Span::raw(format!("{title:<40}")),
                    Span::styled(preview, Style::new().fg(Color::DarkGray).add_modifier(Modifier::ITALIC)),
                ]))
            })
            .collect();
        let list = List::new(items)
            .block(Block::bordered().title(" cxwatch · pick a session "))
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
            .highlight_symbol("▌");
        f.render_stateful_widget(list, list_area, &mut self.picker);

        let [left, right] =
            Layout::horizontal([Constraint::Min(1), Constraint::Length(34)]).areas(status_area);
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(" ❯ ", Style::new().fg(Color::Cyan)),
                Span::raw(self.query.clone()),
                Span::styled("█", Style::new().fg(Color::DarkGray)),
            ])),
            left,
        );
        f.render_widget(
            Paragraph::new(Span::styled(
                format!(
                    "{}/{} sessions · semantic {} ",
                    self.filtered.len(),
                    self.sessions.len(),
                    if self.semantic_on { "on" } else { "off" }
                ),
                Style::new().fg(Color::DarkGray),
            ))
            .right_aligned(),
            right,
        );

        self.draw_help(f, keys_area, " type to filter · ↑↓ move · enter analyze · ^e estate audit · tab semantic · esc quit");
    }

    fn draw_pane(&mut self, f: &mut Frame) {
        let pane = self.pane.as_mut().expect("pane");
        let head_h = pane.header.len() as u16 + 2;
        let [head, body, keys_area] =
            Layout::vertical([Constraint::Length(head_h), Constraint::Min(1), Constraint::Length(1)]).areas(f.area());
        f.render_widget(
            Paragraph::new(pane.header.clone()).block(Block::bordered().title(pane.block_title)),
            head,
        );
        let list = List::new(pane.lines.clone()).highlight_style(Style::new().add_modifier(Modifier::REVERSED));
        f.render_stateful_widget(list, body, &mut pane.list);
        let help = if pane.fixes.is_empty() {
            " ↑↓ scroll · e export md · esc back · q quit"
        } else {
            " ↑↓ scroll · enter show fix · e export md · esc back · q quit"
        };
        self.draw_help(f, keys_area, help);
    }

    fn draw_help(&self, f: &mut Frame, area: Rect, help: &str) {
        let line = match &self.flash {
            Some(msg) => Span::styled(format!(" {msg}"), Style::new().fg(Color::Yellow)),
            None => Span::styled(help.to_string(), Style::new().fg(Color::DarkGray)),
        };
        f.render_widget(Paragraph::new(Line::from(line)), area);
    }
}

fn selected_zero() -> ListState {
    let mut l = ListState::default();
    l.select(Some(0));
    l
}

fn semantic_lines(out: &mut Vec<Line<'static>>, sem: &crate::Semantic, second_label: &str) {
    out.push(Line::default());
    out.push(Line::from(Span::styled(
        format!(" semantic analysis ({})", sem.model_used),
        Style::new().fg(Color::Magenta).add_modifier(Modifier::BOLD),
    )));
    out.push(Line::from(Span::styled(" contradictions:", Style::new().fg(Color::DarkGray))));
    for l in sem.contradiction.lines() {
        out.push(Line::raw(format!("   {l}")));
    }
    out.push(Line::from(Span::styled(format!(" {second_label}:"), Style::new().fg(Color::DarkGray))));
    for l in sem.bloating.lines() {
        out.push(Line::raw(format!("   {l}")));
    }
}

// ----- report pane content -----

fn report_header(meta: &SessionMeta, r: &Report) -> Vec<Line<'static>> {
    let s = &r.summary;
    vec![
        Line::from(Span::styled(
            format!("[{}] {}", meta.source.label(), meta.title),
            Style::new().add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(r.session.clone(), Style::new().fg(Color::DarkGray))),
        Line::from(vec![
            Span::raw(format!(
                "events {} · session ≈{} tok · ",
                s.total_events,
                crate::tok_fmt(s.session_tokens)
            )),
            Span::styled(
                format!(
                    "{} findings · ≈{} tok reclaimable ({}%)",
                    s.findings,
                    crate::tok_fmt(s.reclaimable_tokens),
                    s.reclaimable_pct
                ),
                Style::new().fg(if s.findings == 0 { Color::Green } else { Color::Yellow }),
            ),
        ]),
    ]
}

fn report_lines(r: &Report) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    if r.findings.is_empty() {
        out.push(Line::from(Span::styled(
            " ✔ no mechanical rot detected — context is clean",
            Style::new().fg(Color::Green),
        )));
    }
    for f in &r.findings {
        out.push(Line::from(vec![
            Span::styled(
                format!(" {:<16}", f.rule),
                Style::new().fg(rule_color(f.rule)).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("{:>7} ", format!("~{}", crate::tok_fmt(f.tokens)))),
            Span::styled(format!("{:>6} ", format!("#{}", f.event_idx)), Style::new().fg(Color::DarkGray)),
            Span::raw(f.detail.clone()),
        ]));
    }
    if let Some(sem) = &r.semantic {
        semantic_lines(&mut out, sem, "bloating");
    }
    out
}

// ----- estate pane content -----

fn estate_header(r: &crate::estate::EstateReport) -> Vec<Line<'static>> {
    let s = &r.summary;
    let mut out = vec![
        Line::from(vec![
            Span::styled("context estate audit", Style::new().add_modifier(Modifier::BOLD)),
            Span::styled(
                format!(
                    "   static context vs usage in {} claude · {} codex · {} pi sessions",
                    s.sessions_claude, s.sessions_codex, s.sessions_pi
                ),
                Style::new().fg(Color::DarkGray),
            ),
        ]),
        Line::from(Span::styled(
            format!(
                "units {} · {} findings · ≈{} tok flagged",
                s.units,
                s.findings,
                crate::tok_fmt(s.tokens_flagged)
            ),
            Style::new().fg(if s.findings == 0 { Color::Green } else { Color::Yellow }),
        )),
    ];
    // stacked bar: flagged tokens by category
    let total: usize = r.findings.iter().map(|f| f.tokens).sum();
    if total > 0 {
        const BAR_W: usize = 100;
        let mut bar = Vec::new();
        let mut legend = Vec::new();
        for (rule, _) in crate::estate::GROUPS {
            let group: Vec<_> = r.findings.iter().filter(|f| f.rule == rule).collect();
            if group.is_empty() {
                continue;
            }
            let tokens: usize = group.iter().map(|f| f.tokens).sum();
            if tokens > 0 {
                bar.push(Span::styled(
                    "█".repeat((tokens * BAR_W / total).max(1)),
                    Style::new().fg(rule_color(rule)),
                ));
            }
            legend.push(Span::styled("■ ", Style::new().fg(rule_color(rule))));
            let amount = if tokens > 0 {
                format!("~{}", crate::tok_fmt(tokens))
            } else {
                format!("{}×", group.len())
            };
            legend.push(Span::styled(format!("{rule} {amount}  "), Style::new().fg(Color::DarkGray)));
        }
        out.push(Line::from(bar));
        out.push(Line::from(legend));
    }
    out
}

fn estate_lines(r: &crate::estate::EstateReport) -> (Vec<Line<'static>>, Vec<Option<String>>) {
    let mut out = Vec::new();
    let mut fixes = Vec::new();
    if r.findings.is_empty() {
        out.push(Line::from(Span::styled(" ✔ estate is clean", Style::new().fg(Color::Green))));
        fixes.push(None);
    }
    for f in &r.findings {
        out.push(Line::from(vec![
            Span::styled(
                format!(" {:<20}", f.rule),
                Style::new().fg(rule_color(f.rule)).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("{:>7} ", crate::estate::tok_or_unknown(f.tokens))),
            Span::styled(format!("{:>4} ", format!("{}×", f.uses)), Style::new().fg(Color::DarkGray)),
            Span::raw(format!("{} — {} ", f.unit, f.detail)),
            Span::styled(format!("→ {}", f.action), Style::new().fg(Color::Green)),
        ]));
        fixes.push(Some(f.fix.clone()));
    }
    if let Some(sem) = &r.semantic {
        semantic_lines(&mut out, sem, "duplication");
    }
    (out, fixes)
}

fn rule_color(rule: &str) -> Color {
    match rule {
        "stale-read" | "dead-skill" | "dead-mcp" => Color::Red,
        "superseded-read" | "duplicate-directive" | "dead-command" | "heavy-block" => Color::Yellow,
        "huge-thinking" | "orphan-memory" | "dangling-index" | "stale-ref" => Color::Magenta,
        "huge-output" | "hook-tax" | "stale-memory" => Color::Blue,
        _ => Color::White,
    }
}

fn source_color(s: Source) -> Color {
    match s {
        Source::Pi => Color::Magenta,
        Source::Claude => Color::Cyan,
        Source::Codex => Color::Green,
        Source::OpenCode => Color::Yellow,
    }
}
