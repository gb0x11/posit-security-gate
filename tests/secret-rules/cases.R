# Secret-rule test cases (fake values). Lines 2-5 must be flagged; lines 6-9 must not.
db_password <- "Zr8vQ2mX7kLp4Tn9Wc3Hb6Yd1Fg5Js0e"
api.key = 'Hq3Lw9Xe2Rt7Yu5Io1Pa6Sd4Fg8Jk0Zm'
Sys.setenv(OPENAI_API_TOKEN = "Mn4Bv8Cx2Zl6Kj0Hg3Fd7Sa1Qw5Er9Ty")
cfg$client_secret <<- "Pq7Wo3Ei9Ru1Ty5Yu2Ui8Io4Op6As0Df"
ok1 <- Sys.getenv("DB_PASSWORD")
ok2_password <- "xxxxxxxx"
ok3_token <- "<your-token-here>"
ok4_pwd <- input$password
