/*
    betterdiscord requires everything to be in one file.
    i'm obviously not going to paste my dependencies into my code, so this compiler bundles everything into a nice JS file for use.
    meow
*/

const fs = require("fs");
const compilationOrder = require("./src/compilationOrder.json");

let src = "";

for (let file of compilationOrder) {
    src += fs.readFileSync(`src/${file}`) + "\n";
}

fs.writeFileSync("compiled/esex.plugin.js", src);