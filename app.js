const express = require("express");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const app = express();
const authRouter = require("./routes/auth");

dotenv.config();
app.use(express.json());

mongoose
  .connect("mongodb://localhost:27017")
  .then(() => {
    console.log("Connect success");
  })
  .catch((err) => {
    console.log(err);
  });

app.get("/", () => {
  console.log("Hello");
});

app.use("/auth", authRouter);

app.listen(3000, () => {
  console.log("The server is on port 3000");
});
