//! Windows: el icono y los datos del programa dentro del .exe (los enseñan el Explorador y la
//! barra de tareas). Para los demás sistemas no hace nada.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut res = winresource::WindowsResource::new();
    res.set_icon("assets/icon.ico");
    res.set("FileDescription", "Dotrino Vault");
    res.set("ProductName", "Dotrino Vault");
    if let Err(e) = res.compile() {
        // Sin icono el programa funciona igual, pero el fallo se dice.
        println!("cargo:warning=could not embed the Windows icon: {e}");
    }
}
