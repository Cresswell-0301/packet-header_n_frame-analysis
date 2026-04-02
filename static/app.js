const resetBtn = document.getElementById("reset-btn");
const captureForm = document.getElementById("capture-form");
const scoreForm = document.getElementById("score-form");
const captureLargeBtn = document.getElementById("capture-large-btn");
const statusBadge = document.getElementById("status-badge");
const resultMessage = document.getElementById("result-message");
const stdoutBox = document.getElementById("stdout-box");
const stderrBox = document.getElementById("stderr-box");

function resetForm() {
    // Reset input values
    document.getElementById("pcap_file").value = "capture_live.pcap";
    document.getElementById("seconds").value = "10";
    document.getElementById("features_csv").value = "features.csv";
    document.getElementById("scored_csv").value = "scores.csv";
    document.getElementById("flows_csv").value = "flows.csv";

    // Reset output boxes
    stdoutBox.textContent = "Waiting for action...";
    stderrBox.textContent = "Waiting for action...";

    // Reset status
    setStatus("idle", "Form reset to default.");

    // Reset main button
    setHeroButton("idle");
}

function setStatus(state, message) {
    statusBadge.className = `badge ${state}`;
    statusBadge.textContent = state.charAt(0).toUpperCase() + state.slice(1);
    resultMessage.textContent = message;
    resultMessage.className = `result-message ${state === "error" ? "" : "muted"}`;
}

function setHeroButton(state) {
    if (state === "capturing") {
        captureLargeBtn.textContent = "Capturing";
        captureLargeBtn.disabled = true;
        resetBtn.disabled = true;
    } else if (state === "analyzing") {
        captureLargeBtn.textContent = "Analyzing";
        captureLargeBtn.disabled = true;
        resetBtn.disabled = true;
    } else if (state === "success") {
        captureLargeBtn.textContent = "Recapture";
        captureLargeBtn.disabled = false;
        resetBtn.disabled = false;
    } else {
        captureLargeBtn.textContent = "Start Capture";
        captureLargeBtn.disabled = false;
        resetBtn.disabled = false;
    }
}

async function postForm(url, formData) {
    const response = await fetch(url, {
        method: "POST",
        body: formData,
    });

    const data = await response.json();
    return { response, data };
}

async function runCaptureAndScore() {
    const captureData = new FormData(captureForm);
    const scoreData = new FormData(scoreForm);

    setStatus("running", "Capturing traffic...");
    setHeroButton("capturing");
    stdoutBox.textContent = "Running capture...";
    stderrBox.textContent = "Running capture...";

    try {
        const captureResult = await postForm("/api/start-capture", captureData);
        const captureResponse = captureResult.response;
        const captureJson = captureResult.data;

        stdoutBox.textContent = captureJson.stdout || "No standard output.";
        stderrBox.textContent = captureJson.stderr || "No standard error.";

        if (!captureResponse.ok || !captureJson.ok) {
            setStatus("error", captureJson.message || "Capture failed.");
            setHeroButton("idle");
            return;
        }

        setStatus("running", "Capture completed. Running scoring...");
        setHeroButton("analyzing");
        stdoutBox.textContent += "\n\n--- Scoring started ---";

        const scoreResult = await postForm("/api/score", scoreData);
        const scoreResponse = scoreResult.response;
        const scoreJson = scoreResult.data;

        stdoutBox.textContent = (captureJson.stdout || "No standard output.") + "\n\n--- Scoring Output ---\n" + (scoreJson.stdout || "No standard output.");

        stderrBox.textContent = (captureJson.stderr || "No standard error.") + "\n\n--- Scoring Error ---\n" + (scoreJson.stderr || "No standard error.");

        if (!scoreResponse.ok || !scoreJson.ok) {
            setStatus("error", scoreJson.message || "Scoring failed.");
            setHeroButton("idle");
            return;
        }

        setStatus("success", "Capture and scoring completed successfully.");
        setHeroButton("success");
    } catch (error) {
        stdoutBox.textContent = "No standard output.";
        stderrBox.textContent = error.message;
        setStatus("error", "Unexpected error while processing the request.");
        setHeroButton("idle");
    }
}

captureLargeBtn.addEventListener("click", async () => {
    await runCaptureAndScore();
});

resetBtn.addEventListener("click", () => {
    resetForm();
});
