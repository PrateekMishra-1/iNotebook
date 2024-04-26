const connectToMongo = require('./db.js')
connectToMongo();
const express = require('express')
const cors = require('cors')
const port = 5000

const app = express()
app.use(cors())
app.use(express.json())

app.use("/api/auth" , require("./routes/auth"))
app.use("/api/notes" , require("./routes/notes"))


app.listen(port, () => {
  console.log(`iNotebook backend listening on port http://localhost:${port}`)
})