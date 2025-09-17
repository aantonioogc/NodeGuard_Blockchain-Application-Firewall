// mock_sse.js
const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors());

app.get("/events", (req, res) => {
  res.set({
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });
  res.flushHeaders();

  let counter = 1;

  const interval = setInterval(() => {
    const event = {
      type: "block",
      reason: "mempool_spam",
      clientIp: `192.168.0.${counter}`,
      timestamp: Date.now(),
    };
    console.log("Emitido evento mock", event);

    res.write(`data: ${JSON.stringify(event)}\n\n`);
    counter++;
  }, 5000);

  req.on("close", () => {
    clearInterval(interval);
    console.log("Cliente SSE desconectado");
  });
});

app.listen(3000, () => {
  console.log("Mock SSE server en http://localhost:3000/events");
});

