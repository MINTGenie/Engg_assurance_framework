const express = require("express");
const _ = require("lodash");
const fs = require("fs");

const app = express();
var unusedCounter = 0;

app.get("/calc", (req, res) => {
  // planted: eval of request input
  const result = eval(req.query.expr);
  res.send(String(result));
});

app.get("/vehicle", (req, res) => {
  const id = req.query.id;
  // planted: loose equality, duplicate key, assignment in condition
  if (id == 0) {
    res.send("invalid");
    return;
  }
  const record = { id: id, name: "n/a", id: Number(id) };
  let found;
  if ((found = _.get(record, "name"))) {
    res.send(found);
  }
});

function schedule(task) {
  // planted: implied eval
  setTimeout("run(" + task + ")", 100);
  return;
  console.log("unreachable");
}

function isNumber(value) {
  // planted: typo in typeof comparison, comparison with NaN
  if (typeof value === "nubmer") {
    return true;
  }
  return value === NaN;
}

app.listen(3000);
