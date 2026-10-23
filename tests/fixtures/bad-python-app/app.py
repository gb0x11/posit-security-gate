from shiny import App, render, ui

app_ui = ui.page_fluid(
    ui.h2("Posit security gate - test app"),
    ui.input_slider("n", "N", min=1, max=100, value=20),
    ui.output_text_verbatim("txt"),
)


def server(input, output, session):
    @render.text
    def txt():
        return f"n * 2 = {input.n() * 2}"


app = App(app_ui, server)
