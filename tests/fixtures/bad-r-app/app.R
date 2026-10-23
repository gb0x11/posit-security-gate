# Deliberately insecure test file for the Posit security gate - DO NOT reuse.
# The credential below is fake and random; it exists only to trip secret scanners.
library(shiny)
db_password <- "Zr8vQ2mX7kLp4Tn9Wc3Hb6Yd1Fg5Js0e"
shinyApp(fluidPage("hi"), function(input, output) {})
