//! Dotrino Vault — la ventana de control de la bóveda (Linux, macOS y Windows).
//!
//! Esta app no sabe nada de la bóveda. Lanza el puente (`dotrino-vaultd --gui-bridge`, el
//! mismo binario de la bóveda) y le habla por sus tuberías, una línea JSON por mensaje (ver
//! `src/tui/gui.js`). El puente corre LA MISMA sesión que la TUI y le manda qué pintar: las
//! pantallas, las filas, los avisos y las acciones salen de las mismas funciones. Aquí solo
//! se dibujan con controles de ventana: filas que se pulsan, botones, diálogos y el QR como
//! imagen.
//!
//! - Sin puertos: el canal son las tuberías del hijo.
//! - Al cerrar la ventana el puente ve cerrarse su entrada y vuelve a cerrar las bóvedas que
//!   se abrieron aquí, igual que la TUI al salir.
//! - Los atajos de teclado son los de la TUI (`p` emparejar, `n` nueva…): el botón dice la
//!   tecla.

// Windows: una app de ventanas, no de consola (sin la ventana negra detrás).
#![cfg_attr(windows, windows_subsystem = "windows")]

use std::path::PathBuf;

use iced::keyboard::{self, Key, key::Named};
use iced::widget::{
    button, column, container, mouse_area, opaque, qr_code, rich_text, row, scrollable, space, span, stack, svg,
    text, text_input,
};
use iced::{Border, Color, Element, Font, Length, Subscription, Task, Theme, font, theme, window};
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

const VERSION: &str = env!("CARGO_PKG_VERSION");
// Instancias fijas de las fuentes variables del tema: el motor de texto no elige el peso de
// una variable y caía a la fuente del sistema.
const QUICKSAND: &[u8] = include_bytes!("../assets/Quicksand-Regular.ttf");
const QUICKSAND_BOLD: &[u8] = include_bytes!("../assets/Quicksand-Bold.ttf");
const COMFORTAA: &[u8] = include_bytes!("../assets/Comfortaa-Bold.ttf");
const ICON_SVG: &[u8] = include_bytes!("../assets/icon.svg");
const ICON_PNG: &[u8] = include_bytes!("../assets/icon-512.png");

const BODY: Font = Font::with_name("Quicksand");
const BRAND: Font = Font { family: font::Family::Name("Comfortaa"), weight: font::Weight::Bold, ..Font::DEFAULT };
const BOLD: Font = Font { family: font::Family::Name("Quicksand"), weight: font::Weight::Bold, ..Font::DEFAULT };

fn main() -> iced::Result {
    // Lanzado por el inicio de sesión: solo arranca la bóveda (sin ventana) y se va.
    if std::env::args().any(|a| a == "--start-daemon") {
        start_daemon_detached();
        return Ok(());
    }
    let icon = window::icon::from_file_data(ICON_PNG, None).ok();
    iced::application(App::boot, App::update, App::view)
        .title(App::title)
        .subscription(App::subscription)
        .theme(App::theme)
        .font(QUICKSAND)
        .font(QUICKSAND_BOLD)
        .font(COMFORTAA)
        .default_font(BODY)
        .window(window::Settings {
            size: iced::Size::new(980.0, 680.0),
            min_size: Some(iced::Size::new(560.0, 420.0)),
            icon,
            ..Default::default()
        })
        .run()
}

// ------------------------------- el modelo ----------------------------------

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
struct Sp {
    t: String,
    #[serde(default)]
    c: Option<String>,
    #[serde(default)]
    b: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
struct Row {
    text: Vec<Sp>,
    sel: bool,
    idx: i64,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
struct Line {
    text: Vec<Sp>,
    kind: String,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
struct Tab {
    key: String,
    label: String,
    active: bool,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
struct HelpSeg {
    key: String,
    label: String,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
struct Active {
    name: String,
    protected: bool,
    locked: bool,
    #[serde(default)]
    fingerprint: String,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
struct InputReq {
    label: String,
    hint: String,
    mask: bool,
    value: String,
    #[serde(default)]
    file: bool,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
struct ConfirmReq {
    text: Vec<Sp>,
    default_yes: bool,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
struct View {
    #[serde(default)]
    lang: String,
    #[serde(default)]
    down: bool,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    daemon_up: bool,
    #[serde(default)]
    daemon_text: String,
    #[serde(default)]
    dir: String,
    #[serde(default)]
    screen: String,
    #[serde(default)]
    active: Option<Active>,
    #[serde(default)]
    active_label: String,
    #[serde(default)]
    notice: Option<Line>,
    #[serde(default)]
    tabs: Option<Vec<Tab>>,
    #[serde(default)]
    title: String,
    #[serde(default)]
    rows: Option<Vec<Row>>,
    #[serde(default)]
    selected: i64,
    #[serde(default)]
    body: Option<Vec<Vec<Sp>>>,
    #[serde(default)]
    qr: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    status: Option<Line>,
    #[serde(default)]
    help: Vec<HelpSeg>,
    #[serde(default)]
    input: Option<InputReq>,
    #[serde(default)]
    confirm: Option<ConfirmReq>,
}

#[derive(Debug, Deserialize)]
struct Wire {
    t: String,
    #[serde(default)]
    v: Option<View>,
    #[serde(default)]
    relaunch: bool,
}

// ------------------------------ los mensajes --------------------------------

#[derive(Debug, Clone)]
enum Bridge {
    Ready(mpsc::UnboundedSender<String>),
    View(Box<View>),
    Bye { relaunch: bool },
    Failed(String),
}

#[derive(Debug, Clone)]
enum Message {
    Bridge(Bridge),
    /// Una tecla con el nombre que entiende la TUI (`term.js`).
    Key { name: String, ch: Option<String> },
    RowClick(i64),
    RowActivate(i64),
    Tab(String),
    /// Un botón de acción: su tecla tal como la escribe la ayuda de la TUI («p», «Enter», «F5»).
    Action(String),
    InputChanged(String),
    InputSubmit,
    InputCancel,
    PickFile,
    FilePicked(Option<String>),
    Confirm(bool),
    Mode(theme::Mode),
    Copy(String),
    Open(&'static str),
    Retry,
}

// --------------------------------- la app -----------------------------------

struct App {
    view: Option<View>,
    tx: Option<mpsc::UnboundedSender<String>>,
    /// Sube cada vez que hay que relanzar el puente (tras actualizar): cambia la suscripción.
    generation: u64,
    failed: Option<String>,
    input_value: String,
    /// Para reconocer una pregunta NUEVA y no pisar lo que se está escribiendo.
    input_key: Option<String>,
    qr: Option<(String, qr_code::Data)>,
    mode: theme::Mode,
    copied: Option<String>,
}

fn input_id() -> iced::widget::Id {
    iced::widget::Id::new("vault-input")
}

impl App {
    fn boot() -> (Self, Task<Message>) {
        let app = App {
            view: None,
            tx: None,
            generation: 0,
            failed: None,
            input_value: String::new(),
            input_key: None,
            qr: None,
            mode: theme::Mode::Light,
            copied: None,
        };
        (app, iced::system::theme().map(Message::Mode))
    }

    fn title(&self) -> String {
        match self.view.as_ref().and_then(|v| v.active.as_ref()) {
            Some(a) => format!("{} · Dotrino Vault", a.name),
            None => "Dotrino Vault".into(),
        }
    }

    fn theme(&self) -> Theme {
        cozy(self.mode)
    }

    fn subscription(&self) -> Subscription<Message> {
        Subscription::batch([
            Subscription::run_with(self.generation, bridge_stream).map(Message::Bridge),
            keyboard::listen().filter_map(key_message),
            iced::system::theme_changes().map(Message::Mode),
        ])
    }

    fn send(&self, json: String) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(json);
        }
    }

    fn send_key(&self, name: &str, ch: Option<&str>) {
        let msg = match ch {
            Some(c) => serde_json::json!({ "key": { "name": name, "ch": c } }),
            None => serde_json::json!({ "key": { "name": name } }),
        };
        self.send(msg.to_string());
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Bridge(Bridge::Ready(tx)) => {
                self.tx = Some(tx);
                self.failed = None;
            }
            Message::Bridge(Bridge::View(v)) => {
                let v = *v;
                // El QR se calcula una vez por enlace, no en cada pintado.
                match &v.qr {
                    Some(url) if self.qr.as_ref().map(|(u, _)| u != url).unwrap_or(true) => {
                        self.qr = qr_code::Data::new(url.as_bytes()).ok().map(|d| (url.clone(), d));
                    }
                    None => self.qr = None,
                    _ => {}
                }
                let mut task = Task::none();
                match &v.input {
                    Some(inp) => {
                        let key = format!("{}\u{1}{}", inp.label, inp.hint);
                        if self.input_key.as_deref() != Some(key.as_str()) {
                            self.input_key = Some(key);
                            self.input_value = inp.value.clone();
                            task = iced::widget::operation::focus(input_id());
                        }
                    }
                    None => self.input_key = None,
                }
                self.view = Some(v);
                return task;
            }
            Message::Bridge(Bridge::Bye { relaunch }) => {
                self.tx = None;
                if relaunch {
                    self.generation += 1;
                    self.view = None;
                } else {
                    return iced::exit();
                }
            }
            Message::Bridge(Bridge::Failed(e)) => {
                self.tx = None;
                self.failed = Some(e);
            }
            Message::Retry => {
                self.failed = None;
                self.generation += 1;
            }
            Message::Key { name, ch } => {
                let Some(v) = &self.view else { return Task::none() };
                if v.input.is_some() {
                    // Con una pregunta abierta, el campo se queda las teclas; Esc la cancela.
                    if name == "escape" {
                        self.send_key("escape", None);
                    }
                    return Task::none();
                }
                // `q` cierra la TUI; en una ventana se cierra la ventana.
                if !v.down && ch.as_deref().map(|c| c.eq_ignore_ascii_case("q")).unwrap_or(false) {
                    return Task::none();
                }
                self.send_key(&name, ch.as_deref());
            }
            Message::RowClick(idx) => {
                let Some(v) = &self.view else { return Task::none() };
                if click_activates(&v.screen) {
                    self.send(serde_json::json!({ "activate": idx }).to_string());
                } else {
                    self.send(serde_json::json!({ "select": idx }).to_string());
                }
            }
            Message::RowActivate(idx) => self.send(serde_json::json!({ "activate": idx }).to_string()),
            Message::Tab(key) => self.send(serde_json::json!({ "tab": key }).to_string()),
            Message::Action(k) => {
                let (name, ch) = key_of_token(&k);
                self.send_key(&name, ch.as_deref());
            }
            Message::InputChanged(s) => self.input_value = s,
            Message::InputSubmit => {
                self.send(serde_json::json!({ "submit": self.input_value }).to_string());
                self.input_value.clear();
                self.input_key = None;
            }
            Message::InputCancel => self.send_key("escape", None),
            Message::PickFile => {
                return Task::perform(
                    async {
                        rfd::AsyncFileDialog::new()
                            .pick_file()
                            .await
                            .map(|f| f.path().to_string_lossy().into_owned())
                    },
                    Message::FilePicked,
                );
            }
            Message::FilePicked(Some(p)) => self.input_value = p,
            Message::FilePicked(None) => {}
            Message::Confirm(yes) => self.send(serde_json::json!({ "confirm": yes }).to_string()),
            Message::Mode(m) => {
                if m != theme::Mode::None {
                    self.mode = m
                }
            }
            Message::Open(url) => {
                let _ = open::that_detached(url);
            }
            Message::Copy(s) => {
                self.copied = Some(s.clone());
                return iced::clipboard::write(s);
            }
        }
        Task::none()
    }

    fn view(&self) -> Element<'_, Message> {
        let pal = Pal::of(self.mode);
        let content: Element<'_, Message> = if let Some(err) = &self.failed {
            self.failed_view(err, pal)
        } else {
            match &self.view {
                None => center_text(if es() { "Abriendo la bóveda…" } else { "Opening the vault…" }, pal),
                Some(v) if v.down => self.down_view(v, pal),
                Some(v) => self.main_view(v, pal),
            }
        };
        let base = container(content).width(Length::Fill).height(Length::Fill).style(move |_| container::Style {
            background: Some(pal.bg.into()),
            text_color: Some(pal.text),
            ..Default::default()
        });
        // Las preguntas van encima, en un diálogo.
        let modal = self.view.as_ref().and_then(|v| self.modal(v, pal));
        match modal {
            Some(m) => stack![base, opaque(m)].into(),
            None => base.into(),
        }
    }

    // ------------------------------ pantallas -------------------------------

    fn main_view<'a>(&'a self, v: &'a View, pal: Pal) -> Element<'a, Message> {
        let mut col = column![self.top_bar(v, pal)].spacing(0);
        if let Some(n) = &v.notice {
            col = col.push(banner(&n.text, &n.kind, pal));
        }
        col = col.push(self.nav_bar(v, pal));
        let body: Element<'a, Message> = if let Some(rows) = &v.rows {
            self.rows_view(v, rows, pal)
        } else if let Some(body) = &v.body {
            self.body_view(v, body, pal)
        } else {
            space().into()
        };
        col = col.push(container(body).padding([4, 20]).width(Length::Fill).height(Length::Fill));
        col = col.push(self.status_bar(v, pal));
        col = col.push(self.action_bar(v, pal));
        col.into()
    }

    fn top_bar<'a>(&'a self, v: &'a View, pal: Pal) -> Element<'a, Message> {
        let logo = svg(svg::Handle::from_memory(ICON_SVG)).width(28).height(28);
        let brand = text("Dotrino Vault").font(BRAND).size(19).color(pal.accent);
        let mut left = row![logo, brand].spacing(10).align_y(iced::Alignment::Center);
        if let Some(a) = &v.active {
            let lock = if !a.protected {
                ""
            } else if a.locked {
                " 🔒"
            } else {
                " 🔓"
            };
            left = left.push(space().width(14));
            left = left.push(
                container(text(format!("{}{lock}", a.name)).font(BOLD).size(14))
                    .padding([4, 12])
                    .style(move |_| chip(pal.accent_soft, pal.accent_soft_ink)),
            );
        }
        let dot_color = if v.daemon_up { pal.ok } else { pal.danger };
        let daemon = row![
            text("●").color(dot_color).size(12),
            text(format!("{} {}", v.daemon_text, v.version.clone().unwrap_or_default())).size(13).color(pal.text_dim)
        ]
        .spacing(6)
        .align_y(iced::Alignment::Center);
        let lang = lang_toggle(&v.lang, pal);
        let bar = row![left, space().width(Length::Fill), daemon, space().width(16), lang]
            .align_y(iced::Alignment::Center)
            .padding([10, 20]);
        container(bar)
            .width(Length::Fill)
            .style(move |_| container::Style {
                background: Some(pal.surface.into()),
                border: Border { color: pal.line_soft, width: 0.0, radius: 0.0.into() },
                ..Default::default()
            })
            .into()
    }

    /// Pestañas de la bóveda entrada, o el título de la pantalla, con el «volver» delante.
    fn nav_bar<'a>(&'a self, v: &'a View, pal: Pal) -> Element<'a, Message> {
        let back = v.help.iter().find(|h| h.key == "Esc");
        let mut r = row![].spacing(8).align_y(iced::Alignment::Center);
        if let Some(b) = back {
            r = r.push(
                button(text(format!("← {}", capitalize(&b.label))).size(14))
                    .padding([6, 12])
                    .style(move |_, st| ghost(pal, st))
                    .on_press(Message::Action("Esc".into())),
            );
            r = r.push(space().width(6));
        }
        if let Some(tabs) = &v.tabs {
            for t in tabs {
                let active = t.active;
                let b = button(text(t.label.clone()).size(15).font(if active { BOLD } else { BODY }))
                    .padding([7, 16])
                    .style(move |_, st| tab_style(pal, active, st))
                    .on_press(Message::Tab(t.key.clone()));
                r = r.push(b);
            }
        } else if !v.title.is_empty() {
            r = r.push(text(v.title.clone()).font(BOLD).size(18).color(pal.text));
        }
        container(r).padding([12, 20]).width(Length::Fill).into()
    }

    fn rows_view<'a>(&'a self, v: &'a View, rows: &'a [Row], pal: Pal) -> Element<'a, Message> {
        let mut col = column![].spacing(2);
        for r in rows {
            let (indent, spans) = strip_indent(&r.text);
            if spans.iter().all(|s| s.t.trim().is_empty()) {
                col = col.push(space().height(8));
                continue;
            }
            let rt = rich(spans, pal, 15.0);
            if r.sel {
                let selected = r.idx == v.selected;
                let item = container(rt)
                    .padding([9, 14])
                    .width(Length::Fill)
                    .style(move |_| row_style(pal, selected));
                col = col.push(
                    mouse_area(item)
                        .on_press(Message::RowClick(r.idx))
                        .on_double_click(Message::RowActivate(r.idx))
                        .interaction(iced::mouse::Interaction::Pointer),
                );
            } else {
                col = col.push(container(rt).padding(iced::Padding { top: 2.0, bottom: 2.0, left: 14.0 + indent, right: 14.0 }));
            }
        }
        scrollable(container(col).padding(iced::Padding { right: 12.0, ..Default::default() })).height(Length::Fill).into()
    }

    /// Emparejar y unirse: el QR como imagen, y los textos de la TUI al lado.
    fn body_view<'a>(&'a self, v: &'a View, body: &'a [Vec<Sp>], pal: Pal) -> Element<'a, Message> {
        let mut lines = column![].spacing(4);
        for l in body {
            let (indent, spans) = strip_indent(l);
            if spans.iter().all(|s| s.t.trim().is_empty()) {
                lines = lines.push(space().height(6));
                continue;
            }
            lines = lines.push(container(rich(spans, pal, 15.0)).padding(iced::Padding { left: indent, ..Default::default() }));
        }
        let mut copy = row![].spacing(8);
        if let Some(url) = &v.qr {
            copy = copy.push(
                button(text(if es() { "Copiar enlace" } else { "Copy link" }).size(14))
                    .padding([6, 14])
                    .style(move |_, st| primary(pal, st))
                    .on_press(Message::Copy(url.clone())),
            );
        }
        if let Some(code) = v.code.as_ref().filter(|c| !c.is_empty()) {
            copy = copy.push(
                button(text(if es() { "Copiar código" } else { "Copy code" }).size(14))
                    .padding([6, 14])
                    .style(move |_, st| ghost(pal, st))
                    .on_press(Message::Copy(code.clone())),
            );
        }
        if self.copied.is_some() && v.qr.is_some() {
            copy = copy.push(text(if es() { "Copiado" } else { "Copied" }).size(13).color(pal.ok));
        }
        let mut content = row![].spacing(28);
        if let Some((_, data)) = &self.qr {
            let qr = qr_code(data).cell_size(5).style(move |_| qr_code::Style { cell: Color::BLACK, background: Color::WHITE });
            content = content.push(container(qr).padding(12).style(move |_| container::Style {
                background: Some(Color::WHITE.into()),
                border: Border { radius: 16.0.into(), ..Default::default() },
                ..Default::default()
            }));
        }
        content = content.push(column![lines, space().height(10), copy].width(Length::Fill));
        scrollable(content).height(Length::Fill).into()
    }

    fn status_bar<'a>(&'a self, v: &'a View, pal: Pal) -> Element<'a, Message> {
        let Some(s) = &v.status else { return space().height(0).into() };
        let (icon, color) = match s.kind.as_str() {
            "busy" => ("⏳ ", pal.busy),
            "danger" => ("✗ ", pal.danger),
            "warn" => ("! ", pal.busy),
            _ => ("✓ ", pal.ok),
        };
        let mut spans = vec![Sp { t: icon.into(), c: None, b: None }];
        spans.extend(s.text.iter().cloned());
        let line = rich_owned(spans, pal, 14.0, Some(color));
        container(line).padding([8, 20]).width(Length::Fill).into()
    }

    /// Las acciones de la pantalla: las teclas de la ayuda de la TUI, como botones.
    fn action_bar<'a>(&'a self, v: &'a View, pal: Pal) -> Element<'a, Message> {
        let mut r = row![].spacing(8);
        let mut any = false;
        for h in &v.help {
            if skip_action(&h.key) {
                continue;
            }
            any = true;
            let label = capitalize(&h.label);
            let hint = key_hint(&h.key);
            let content = row![text(label).size(14), text(hint).size(11).color(pal.text_faint)]
                .spacing(6)
                .align_y(iced::Alignment::Center);
            let kind = action_kind(&h.key, &h.label);
            r = r.push(
                button(content)
                    .padding([7, 14])
                    .style(move |_, st| match kind {
                        Kind::Primary => primary(pal, st),
                        Kind::Danger => danger_outline(pal, st),
                        Kind::Normal => ghost(pal, st),
                    })
                    .on_press(Message::Action(h.key.clone())),
            );
        }
        if !any {
            return space().height(0).into();
        }
        container(r.wrap())
            .padding([12, 20])
            .width(Length::Fill)
            .style(move |_| container::Style { background: Some(pal.surface.into()), ..Default::default() })
            .into()
    }

    fn down_view<'a>(&'a self, v: &'a View, pal: Pal) -> Element<'a, Message> {
        let mut col = column![
            svg(svg::Handle::from_memory(ICON_SVG)).width(64).height(64),
            text(v.title.clone()).font(BOLD).size(22).color(pal.text),
        ]
        .spacing(14)
        .align_x(iced::Alignment::Center)
        .max_width(560);
        for l in v.body.iter().flatten() {
            col = col.push(rich_owned(l.clone(), pal, 15.0, Some(pal.text_dim)).align_x(iced::Alignment::Center));
        }
        let mut btns = row![].spacing(10);
        for h in &v.help {
            if skip_action(&h.key) {
                continue;
            }
            let primary_btn = h.key.eq_ignore_ascii_case("s");
            btns = btns.push(
                button(text(capitalize(&h.label)).size(15))
                    .padding([9, 18])
                    .style(move |_, st| if primary_btn { primary(pal, st) } else { ghost(pal, st) })
                    .on_press(Message::Action(h.key.clone())),
            );
        }
        col = col.push(space().height(6)).push(btns);
        if let Some(s) = &v.status {
            let color = if s.kind == "danger" { pal.danger } else if s.kind == "busy" { pal.busy } else { pal.busy };
            col = col.push(rich_owned(s.text.clone(), pal, 14.0, Some(color)));
        }
        col = col.push(space().height(10)).push(text(format!("{}  ·  {VERSION}", v.dir)).size(12).color(pal.text_faint));
        let top = row![space().width(Length::Fill), lang_toggle(&v.lang, pal)].padding([10, 20]);
        column![top, container(col).center(Length::Fill)].into()
    }

    fn failed_view<'a>(&'a self, err: &'a str, pal: Pal) -> Element<'a, Message> {
        let (title, body, link) = if es() {
            (
                "No encuentro la bóveda",
                "Esta ventana usa el programa de la bóveda (dotrino-vaultd), que tiene que estar instalado en esta computadora.",
                "Cómo instalarla",
            )
        } else {
            (
                "The vault is not installed",
                "This window uses the vault program (dotrino-vaultd), which has to be installed on this computer.",
                "How to install it",
            )
        };
        let col = column![
            svg(svg::Handle::from_memory(ICON_SVG)).width(64).height(64),
            text(title).font(BOLD).size(22),
            text(body).size(15).color(pal.text_dim).align_x(iced::Alignment::Center),
            text(err.to_string()).size(12).color(pal.text_faint),
            row![
                button(text(link).size(15)).padding([9, 18]).style(move |_, st| primary(pal, st)).on_press(Message::Open(install_url())),
                button(text(if es() { "Reintentar" } else { "Retry" }).size(15))
                    .padding([9, 18])
                    .style(move |_, st| ghost(pal, st))
                    .on_press(Message::Retry),
            ]
            .spacing(10),
        ]
        .spacing(14)
        .align_x(iced::Alignment::Center)
        .max_width(560);
        container(col).center(Length::Fill).into()
    }

    /// La pregunta o la confirmación abierta, como diálogo.
    fn modal<'a>(&'a self, v: &'a View, pal: Pal) -> Option<Element<'a, Message>> {
        let card: Element<'a, Message> = if let Some(inp) = &v.input {
            // El hint ya va encima, entero: repetido como marcador quedaba cortado.
            let field = text_input("", &self.input_value)
                .id(input_id())
                .secure(inp.mask)
                .on_input(Message::InputChanged)
                .on_submit(Message::InputSubmit)
                .padding(10)
                .size(15);
            let mut btns = row![].spacing(8);
            if inp.file {
                btns = btns.push(
                    button(text(if es() { "Elegir archivo…" } else { "Choose file…" }).size(14))
                        .padding([7, 14])
                        .style(move |_, st| ghost(pal, st))
                        .on_press(Message::PickFile),
                );
            }
            btns = btns
                .push(space().width(Length::Fill))
                .push(
                    button(text(if es() { "Cancelar" } else { "Cancel" }).size(14))
                        .padding([7, 14])
                        .style(move |_, st| ghost(pal, st))
                        .on_press(Message::InputCancel),
                )
                .push(
                    button(text(if es() { "Aceptar" } else { "OK" }).size(14))
                        .padding([7, 18])
                        .style(move |_, st| primary(pal, st))
                        .on_press(Message::InputSubmit),
                );
            let mut col = column![text(inp.label.clone()).font(BOLD).size(17)].spacing(12);
            if !inp.hint.is_empty() {
                col = col.push(text(inp.hint.clone()).size(13).color(pal.text_dim));
            }
            col.push(field).push(btns).into()
        } else if let Some(cf) = &v.confirm {
            let (yes, no) = if es() { ("Sí", "No") } else { ("Yes", "No") };
            let dy = cf.default_yes;
            let btns = row![
                space().width(Length::Fill),
                button(text(no).size(14))
                    .padding([7, 18])
                    .style(move |_, st| if dy { ghost(pal, st) } else { primary(pal, st) })
                    .on_press(Message::Confirm(false)),
                button(text(yes).size(14))
                    .padding([7, 18])
                    .style(move |_, st| if dy { primary(pal, st) } else { ghost(pal, st) })
                    .on_press(Message::Confirm(true)),
            ]
            .spacing(8);
            column![rich_owned(cf.text.clone(), pal, 16.0, Some(pal.text)), btns].spacing(18).into()
        } else {
            return None;
        };
        let boxed = container(card).padding(24).max_width(560).style(move |_| container::Style {
            background: Some(pal.surface.into()),
            border: Border { color: pal.line, width: 1.0, radius: 20.0.into() },
            text_color: Some(pal.text),
            ..Default::default()
        });
        Some(
            container(boxed)
                .center(Length::Fill)
                .style(move |_| container::Style {
                    background: Some(Color { a: 0.45, ..Color::BLACK }.into()),
                    ..Default::default()
                })
                .into(),
        )
    }
}

fn center_text<'a>(s: &'a str, pal: Pal) -> Element<'a, Message> {
    container(text(s).size(16).color(pal.text_dim)).center(Length::Fill).into()
}

fn lang_toggle<'a>(lang: &str, pal: Pal) -> Element<'a, Message> {
    // Dos botones con el activo resaltado (CONVENCIONES §9). El otro manda la `l` de la TUI.
    let mk = |code: &'static str| {
        let active = lang == code.to_lowercase();
        let b = button(text(code).size(13).font(if active { BOLD } else { BODY }))
            .padding([4, 10])
            .style(move |_, st| tab_style(pal, active, st));
        if active { b } else { b.on_press(Message::Action("l".into())) }
    };
    row![mk("ES"), mk("EN")].spacing(2).into()
}

fn banner<'a>(spans: &'a [Sp], kind: &str, pal: Pal) -> Element<'a, Message> {
    let (bg, fg) = if kind == "warn" { (pal.warn_soft, pal.text) } else { (pal.surface_2, pal.text_dim) };
    container(rich(spans.to_vec(), pal, 14.0))
        .padding([8, 20])
        .width(Length::Fill)
        .style(move |_| container::Style { background: Some(bg.into()), text_color: Some(fg), ..Default::default() })
        .into()
}

// --------------------------------- texto ------------------------------------

/// Las filas de la TUI sangran con espacios; aquí la sangría se vuelve margen.
fn strip_indent(spans: &[Sp]) -> (f32, Vec<Sp>) {
    let mut out: Vec<Sp> = spans.to_vec();
    let mut n = 0usize;
    while let Some(first) = out.first_mut() {
        let trimmed = first.t.trim_start_matches(' ');
        n += first.t.len() - trimmed.len();
        if trimmed.is_empty() {
            out.remove(0);
            continue;
        }
        // Las casillas de la TUI («[x]», «[ ]») como casillas de verdad.
        first.t = if let Some(rest) = trimmed.strip_prefix("[x]") {
            format!("☑{rest}")
        } else if let Some(rest) = trimmed.strip_prefix("[ ]") {
            format!("☐{rest}")
        } else {
            trimmed.to_string()
        };
        break;
    }
    ((n.saturating_sub(1) as f32) * 4.0, out)
}

fn color_of(c: Option<&str>, pal: Pal) -> Option<Color> {
    match c? {
        "accent" | "title" => Some(pal.accent),
        "ok" => Some(pal.ok),
        "warn" => Some(pal.busy),
        "danger" => Some(pal.danger),
        "muted" => Some(pal.text_faint),
        _ => None,
    }
}

fn rich<'a>(spans: Vec<Sp>, pal: Pal, size: f32) -> iced::widget::text::Rich<'a, (), Message> {
    rich_owned(spans, pal, size, None)
}

fn rich_owned<'a>(spans: Vec<Sp>, pal: Pal, size: f32, base: Option<Color>) -> iced::widget::text::Rich<'a, (), Message> {
    let list: Vec<iced::widget::text::Span<'a, (), Font>> = spans
        .into_iter()
        .map(|s| {
            let color = color_of(s.c.as_deref(), pal).or(base);
            let bold = s.b.unwrap_or(false) || s.c.as_deref() == Some("title");
            span(s.t).color_maybe(color).font(if bold { BOLD } else { BODY })
        })
        .collect();
    rich_text(list).size(size)
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

// --------------------------------- teclas -----------------------------------

/// Lo que no es una acción de la pantalla: moverse (la ventana se mueve con el ratón), el
/// idioma (va arriba) y salir (se cierra la ventana). «Esc» va como «volver», arriba.
fn skip_action(key: &str) -> bool {
    matches!(key, "↑↓" | "←→" | "l" | "q" | "Q" | "Esc") || key.starts_with('↑')
}

/// Las pantallas donde pulsar una fila ya es elegirla (marcar un permiso, cambiar un ajuste).
fn click_activates(screen: &str) -> bool {
    matches!(screen, "caps" | "paircaps" | "settings" | "pairmode" | "doors")
}

#[derive(Clone, Copy)]
enum Kind {
    Primary,
    Danger,
    Normal,
}

fn action_kind(key: &str, label: &str) -> Kind {
    let l = label.to_lowercase();
    if key == "Enter" || key == "S" || key == "G" || key == "g" {
        return Kind::Primary;
    }
    if key == "d" || key == "v" || l.starts_with("revoc") || l.starts_with("borr") || l.starts_with("delete") || l.starts_with("quitar") || l.starts_with("remove") || l.starts_with("rechaz") || l.starts_with("reject") {
        return Kind::Danger;
    }
    Kind::Normal
}

fn key_hint(key: &str) -> String {
    match key {
        "Enter" => "↵".into(),
        "F5" => "F5".into(),
        k => k.to_uppercase(),
    }
}

/// «p» → char p · «Enter» → enter · «F5» → f5 · «n/Esc» → n.
fn key_of_token(tok: &str) -> (String, Option<String>) {
    let first = tok.split('/').next().unwrap_or(tok);
    match first {
        "Enter" => ("enter".into(), None),
        "Esc" => ("escape".into(), None),
        "F5" => ("f5".into(), None),
        k => ("char".into(), Some(k.to_string())),
    }
}

fn key_message(ev: keyboard::Event) -> Option<Message> {
    let keyboard::Event::KeyPressed { key, modifiers, text, .. } = ev else { return None };
    if modifiers.control() || modifiers.alt() || modifiers.logo() {
        return None;
    }
    let named = |n: &str| Some(Message::Key { name: n.into(), ch: None });
    match key {
        Key::Named(Named::ArrowUp) => named("up"),
        Key::Named(Named::ArrowDown) => named("down"),
        Key::Named(Named::ArrowLeft) => named("left"),
        Key::Named(Named::ArrowRight) => named("right"),
        Key::Named(Named::Enter) => named("enter"),
        Key::Named(Named::Escape) => named("escape"),
        Key::Named(Named::F5) => named("f5"),
        Key::Named(Named::PageUp) => named("pageup"),
        Key::Named(Named::PageDown) => named("pagedown"),
        Key::Named(Named::Home) => named("home"),
        Key::Named(Named::End) => named("end"),
        Key::Named(Named::Delete) => named("delete"),
        Key::Named(Named::Space) => Some(Message::Key { name: "char".into(), ch: Some(" ".into()) }),
        Key::Character(_) => {
            let t = text?.to_string();
            if t.chars().all(|c| c.is_control()) {
                return None;
            }
            Some(Message::Key { name: "char".into(), ch: Some(t) })
        }
        _ => None,
    }
}

// --------------------------------- el puente ---------------------------------

/// Cómo se lanza el puente. En orden: `DOTRINO_VAULT_BRIDGE` (desarrollo, la orden entera),
/// el binario de la bóveda al lado de esta app (los instaladores los ponen juntos), y el que
/// haya en el PATH.
fn bridge_command() -> Result<(PathBuf, Vec<String>), String> {
    if let Ok(cmdline) = std::env::var("DOTRINO_VAULT_BRIDGE") {
        let mut parts = cmdline.split_whitespace().map(str::to_string);
        let prog = parts.next().ok_or("DOTRINO_VAULT_BRIDGE is empty")?;
        let mut args: Vec<String> = parts.collect();
        args.push("gui-bridge".into());
        return Ok((PathBuf::from(prog), args));
    }
    let exe = if cfg!(windows) { "dotrino-vaultd.exe" } else { "dotrino-vaultd" };
    if let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(PathBuf::from)) {
        let side = dir.join(exe);
        if side.is_file() {
            return Ok((side, vec!["--gui-bridge".into()]));
        }
    }
    if let Some(p) = which(exe) {
        return Ok((p, vec!["--gui-bridge".into()]));
    }
    // Instalado por npm: `dotrino-vault` es un script de node.
    let ctl = if cfg!(windows) { "dotrino-vault.cmd" } else { "dotrino-vault" };
    if let Some(p) = which(ctl) {
        if cfg!(windows) {
            return Ok((PathBuf::from("cmd.exe"), vec!["/d".into(), "/c".into(), p.to_string_lossy().into_owned(), "gui-bridge".into()]));
        }
        return Ok((p, vec!["gui-bridge".into()]));
    }
    Err(format!("{exe} not found next to this app nor in the PATH"))
}

fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(name)).find(|p| p.is_file())
}

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn bridge_stream(_generation: &u64) -> impl iced::futures::Stream<Item = Bridge> + use<> {
    iced::stream::channel(64, async |mut out: iced::futures::channel::mpsc::Sender<Bridge>| {
        use iced::futures::SinkExt;
        let (prog, args) = match bridge_command() {
            Ok(c) => c,
            Err(e) => {
                let _ = out.send(Bridge::Failed(e)).await;
                return;
            }
        };
        let mut cmd = tokio::process::Command::new(&prog);
        cmd.args(&args).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null());
        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW);
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let _ = out.send(Bridge::Failed(format!("{}: {e}", prog.display()))).await;
                return;
            }
        };
        let mut stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        let _ = out.send(Bridge::Ready(tx)).await;
        // Lo que se escribe al puente va por su propia tarea: leer y escribir no se esperan.
        tokio::spawn(async move {
            while let Some(line) = rx.recv().await {
                if stdin.write_all(line.as_bytes()).await.is_err() || stdin.write_all(b"\n").await.is_err() {
                    break;
                }
                let _ = stdin.flush().await;
            }
            // Al soltarse el emisor (la ventana se cerró), se cierra la entrada del puente:
            // es su señal para volver a cerrar las bóvedas abiertas aquí.
        });
        let mut lines = BufReader::new(stdout).lines();
        let mut said_bye = false;
        while let Ok(Some(line)) = lines.next_line().await {
            let Ok(w) = serde_json::from_str::<Wire>(&line) else { continue };
            match w.t.as_str() {
                "view" => {
                    if let Some(v) = w.v {
                        let _ = out.send(Bridge::View(Box::new(v))).await;
                    }
                }
                "bye" => {
                    said_bye = true;
                    let _ = out.send(Bridge::Bye { relaunch: w.relaunch }).await;
                }
                _ => {}
            }
        }
        let status = child.wait().await;
        if !said_bye {
            let why = match status {
                Ok(s) => format!("the vault bridge exited ({s})"),
                Err(e) => format!("the vault bridge failed: {e}"),
            };
            let _ = out.send(Bridge::Failed(why)).await;
        }
        // La suscripción no debe terminar: se queda quieta hasta que la ventana la cambie.
        std::future::pending::<()>().await;
    })
}

/// `--start-daemon`: lo que pone el inicio de sesión en Windows. Lanza la bóveda sin ventana.
fn start_daemon_detached() {
    let Ok((prog, mut args)) = bridge_command() else { return };
    // Mismo programa que el puente, pero sin el modo puente: así arranca el daemon.
    args.retain(|a| a != "--gui-bridge" && a != "gui-bridge");
    if prog.file_name().map(|n| n.to_string_lossy().starts_with("dotrino-vaultd")).unwrap_or(false) {
        let mut cmd = std::process::Command::new(prog);
        cmd.args(args).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let _ = cmd.spawn();
    }
}

// --------------------------------- idioma -----------------------------------

/// La página del wiki que explica cómo instalar la bóveda, en el idioma del sistema.
fn install_url() -> &'static str {
    if es() { "https://wiki.dotrino.com/vault/instalacion/" } else { "https://wiki.dotrino.com/en/vault/instalacion/" }
}

/// ¿El sistema está en español? Solo para los textos propios de la ventana (los de la bóveda
/// los manda el puente, en el idioma que elegiste en ella).
fn es() -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Globalization::GetUserDefaultUILanguage;
        // LANGID: los 10 bits bajos son el idioma; 0x0a es español.
        return (unsafe { GetUserDefaultUILanguage() } & 0x3ff) == 0x0a;
    }
    #[allow(unreachable_code)]
    {
        let lang = std::env::var("LC_ALL").or_else(|_| std::env::var("LC_MESSAGES")).or_else(|_| std::env::var("LANG")).unwrap_or_default();
        lang.to_lowercase().starts_with("es")
    }
}

// ---------------------------------- tema ------------------------------------

/// «Cool & Cozy» (`@dotrino/theme`): los mismos tokens `--dt-*`, en claro y en oscuro.
#[derive(Clone, Copy)]
struct Pal {
    bg: Color,
    surface: Color,
    surface_2: Color,
    surface_3: Color,
    line: Color,
    line_soft: Color,
    text: Color,
    text_dim: Color,
    text_faint: Color,
    accent: Color,
    accent_press: Color,
    accent_ink: Color,
    accent_soft: Color,
    accent_soft_ink: Color,
    ok: Color,
    busy: Color,
    danger: Color,
    warn_soft: Color,
}

const fn hex(v: u32) -> Color {
    Color::from_rgb8(((v >> 16) & 0xff) as u8, ((v >> 8) & 0xff) as u8, (v & 0xff) as u8)
}

impl Pal {
    fn of(mode: theme::Mode) -> Pal {
        if mode == theme::Mode::Dark {
            Pal {
                bg: hex(0x0f1416),
                surface: hex(0x1c2022),
                surface_2: hex(0x262a2d),
                surface_3: hex(0x313538),
                line: hex(0x3f484e),
                line_soft: hex(0x262a2d),
                text: hex(0xdfe3e6),
                text_dim: hex(0xbfc8cf),
                text_faint: hex(0x899296),
                accent: hex(0x81cfff),
                accent_press: hex(0x5fb8ee),
                accent_ink: hex(0x003549),
                accent_soft: hex(0x004c6b),
                accent_soft_ink: hex(0xc6e7ff),
                ok: hex(0x7ad7c2),
                busy: hex(0xf5b041),
                danger: hex(0xffb4ab),
                warn_soft: hex(0x3d2e10),
            }
        } else {
            Pal {
                bg: hex(0xf7fafc),
                surface: hex(0xffffff),
                surface_2: hex(0xf1f4f6),
                surface_3: hex(0xe9eef1),
                line: hex(0xbfc8cf),
                line_soft: hex(0xe3e9ed),
                text: hex(0x181c1e),
                text_dim: hex(0x3f484e),
                text_faint: hex(0x70787f),
                accent: hex(0x00658c),
                accent_press: hex(0x00506f),
                accent_ink: hex(0xffffff),
                accent_soft: hex(0xd4ecfa),
                accent_soft_ink: hex(0x004e6e),
                ok: hex(0x006b5c),
                busy: hex(0xa35a00),
                danger: hex(0xba1a1a),
                warn_soft: hex(0xfff0d6),
            }
        }
    }
}

fn cozy(mode: theme::Mode) -> Theme {
    let p = Pal::of(mode);
    Theme::custom(
        "Cool & Cozy",
        theme::Palette { background: p.bg, text: p.text, primary: p.accent, success: p.ok, warning: p.busy, danger: p.danger },
    )
}

fn chip(bg: Color, fg: Color) -> container::Style {
    container::Style {
        background: Some(bg.into()),
        text_color: Some(fg),
        border: Border { radius: 999.0.into(), ..Default::default() },
        ..Default::default()
    }
}

fn row_style(pal: Pal, selected: bool) -> container::Style {
    container::Style {
        background: Some(if selected { pal.accent_soft } else { pal.surface }.into()),
        text_color: Some(if selected { pal.accent_soft_ink } else { pal.text }),
        border: Border { color: if selected { pal.accent } else { pal.line_soft }, width: 1.0, radius: 12.0.into() },
        ..Default::default()
    }
}

fn btn(bg: Color, fg: Color, border: Color) -> button::Style {
    button::Style {
        background: Some(bg.into()),
        text_color: fg,
        border: Border { color: border, width: 1.0, radius: 999.0.into() },
        ..Default::default()
    }
}

fn primary(pal: Pal, st: button::Status) -> button::Style {
    let bg = if matches!(st, button::Status::Hovered | button::Status::Pressed) { pal.accent_press } else { pal.accent };
    btn(bg, pal.accent_ink, bg)
}

fn ghost(pal: Pal, st: button::Status) -> button::Style {
    let bg = if matches!(st, button::Status::Hovered | button::Status::Pressed) { pal.surface_3 } else { pal.surface_2 };
    btn(bg, pal.text, pal.line_soft)
}

fn danger_outline(pal: Pal, st: button::Status) -> button::Style {
    let bg = if matches!(st, button::Status::Hovered | button::Status::Pressed) { pal.surface_3 } else { pal.surface_2 };
    btn(bg, pal.danger, pal.danger)
}

fn tab_style(pal: Pal, active: bool, st: button::Status) -> button::Style {
    if active {
        btn(pal.accent_soft, pal.accent_soft_ink, pal.accent_soft)
    } else if matches!(st, button::Status::Hovered | button::Status::Pressed) {
        btn(pal.surface_3, pal.text, pal.surface_3)
    } else {
        btn(Color::TRANSPARENT, pal.text_dim, Color::TRANSPARENT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn las_teclas_de_la_ayuda_se_vuelven_teclas_de_la_tui() {
        assert_eq!(key_of_token("p"), ("char".into(), Some("p".into())));
        assert_eq!(key_of_token("Enter"), ("enter".into(), None));
        assert_eq!(key_of_token("Esc"), ("escape".into(), None));
        assert_eq!(key_of_token("F5"), ("f5".into(), None));
        assert_eq!(key_of_token("n/Esc"), ("char".into(), Some("n".into())));
    }

    #[test]
    fn la_sangria_se_vuelve_margen_y_las_casillas_casillas() {
        let sp = |t: &str| Sp { t: t.into(), c: None, b: None };
        let (indent, out) = strip_indent(&[sp("     "), sp(" [x] firmar")]);
        assert!(indent > 0.0);
        assert_eq!(out[0].t, "☑ firmar");
        let (_, out) = strip_indent(&[sp(" [ ] admin")]);
        assert_eq!(out[0].t, "☐ admin");
    }

    #[test]
    fn moverse_idioma_y_salir_no_son_botones() {
        for k in ["↑↓", "←→", "l", "q", "Q", "Esc"] {
            assert!(skip_action(k), "{k}");
        }
        assert!(!skip_action("p"));
        assert!(!skip_action("Enter"));
    }

    #[test]
    fn el_modelo_del_puente_se_lee() {
        let line = r#"{"t":"view","v":{"lang":"es","screen":"profiles","daemonUp":true,"daemonText":"corriendo","rows":[{"text":[{"t":"A","b":true}],"sel":true,"idx":0}],"selected":0,"help":[{"key":"p","label":"emparejar"}],"input":null,"confirm":null}}"#;
        let w: Wire = serde_json::from_str(line).unwrap();
        let v = w.v.unwrap();
        assert_eq!(v.rows.unwrap()[0].text[0].t, "A");
        assert_eq!(v.help[0].key, "p");
        assert!(v.daemon_up);
    }
}
