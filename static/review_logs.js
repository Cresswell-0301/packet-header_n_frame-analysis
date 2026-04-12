async function loadTablePage({ page = 1, apiUrl, headSelector, bodySelector, paginationSelector, emptyMessage, errorPrefix, reloadFn }) {
    try {
        const res = await fetch(`${apiUrl}?page=${page}`);
        const json = await res.json();

        const head = document.querySelector(headSelector);
        const body = document.querySelector(bodySelector);

        body.innerHTML = "";

        if (!json.data || json.data.length === 0) {
            head.innerHTML = "<tr><th>No data</th></tr>";
            body.innerHTML = `<tr><td>${emptyMessage}</td></tr>`;
            renderPagination(paginationSelector, 1, 1, reloadFn);
            return;
        }

        const columns = json.columns;

        head.innerHTML = `
            <tr>
                ${columns.map((col) => `<th>${col}</th>`).join("")}
            </tr>
        `;

        json.data.forEach((row) => {
            let tr = "<tr>";
            columns.forEach((col) => {
                const value = row[col] ?? "";
                tr += `<td>${value}</td>`;
            });
            tr += "</tr>";
            body.innerHTML += tr;
        });

        const totalPages = Math.ceil(json.total / json.per_page);
        renderPagination(paginationSelector, json.page, totalPages, reloadFn);
    } catch (error) {
        const head = document.querySelector(headSelector);
        const body = document.querySelector(bodySelector);

        head.innerHTML = "<tr><th>Error</th></tr>";
        body.innerHTML = `<tr><td>${errorPrefix}: ${error.message}</td></tr>`;
        console.error(`${errorPrefix}:`, error);
    }
}

function loadPage(page = 1) {
    return loadTablePage({
        page,
        apiUrl: "/api/records",
        headSelector: "#records-table-head",
        bodySelector: "#table-body",
        paginationSelector: "#records-pagination",
        emptyMessage: "No scored records available.",
        errorPrefix: "Failed to load records",
        reloadFn: loadPage,
    });
}

function loadFlowPage(page = 1) {
    return loadTablePage({
        page,
        apiUrl: "/api/flows",
        headSelector: "#flows-table-head",
        bodySelector: "#flows-table-body",
        paginationSelector: "#flows-pagination",
        emptyMessage: "No flow records available.",
        errorPrefix: "Failed to load flow records",
        reloadFn: loadFlowPage,
    });
}

function riskBadgeClass(level) {
    const v = (level || "").toLowerCase();
    if (v === "high" || v === "very high") return "sev-high";
    if (v === "medium") return "sev-medium";
    return "sev-low";
}

function sourceBadge(value) {
    const v = (value || "unknown").toLowerCase();
    return `<span class="soc-badge source-badge">${v.toUpperCase()}</span>`;
}

function severityBadge(value) {
    const text = (value || "low").toUpperCase();
    return `<span class="soc-badge ${riskBadgeClass(value)}">${text}</span>`;
}

function buildSummary(row, proto) {
    if (proto === "http") {
        return `Client requested ${row.flow_http_method || "HTTP"} ${row.flow_http_host || ""}${row.flow_http_path || ""}`.trim();
    }
    if (proto === "tls") {
        return `Observed encrypted web session${row.flow_tls_sni ? ` to ${row.flow_tls_sni}` : ""}`.trim();
    }
    if (proto === "ssh") {
        return `Observed SSH session${row.flow_ssh_banner ? ` with banner ${row.flow_ssh_banner}` : ""}`.trim();
    }
    if (proto === "smb") {
        return `Observed ${row.flow_smb_version || "SMB"} file-sharing traffic`.trim();
    }
    return "Protocol evidence observed.";
}

function loadProtocolPage(page = 1) {
    const protocolFilterEl = document.getElementById("protocol-filter");
    const sourceFilterEl = document.getElementById("detect-source-filter");
    const riskSortFilterEl = document.getElementById("risk-sort-filter");

    const protocol = protocolFilterEl ? protocolFilterEl.value : "all";
    const detectSource = sourceFilterEl ? sourceFilterEl.value : "all";
    const riskSort = riskSortFilterEl ? riskSortFilterEl.value : "desc";

    updateProtocolTitle(protocol, detectSource);

    fetch(
        `/api/protocol-evidence?page=${page}&protocol=${encodeURIComponent(protocol)}&detect_source=${encodeURIComponent(detectSource)}&risk_sort=${encodeURIComponent(riskSort)}`,
    )
        .then((res) => res.json())
        .then((json) => {
            const grid = document.getElementById("protocol-grid");
            grid.innerHTML = "";

            if (!json.data || json.data.length === 0) {
                const message = buildNoDataMessage(protocol, detectSource);
                grid.classList.add("single-col");
                grid.innerHTML = `<div class="muted no-data-msg">${message}</div>`;
                renderPagination("#protocol-pagination", 1, 1, loadProtocolPage);
                return;
            }

            grid.classList.remove("single-col");

            json.data.forEach((row) => {
                const card = document.createElement("div");
                card.className = "protocol-card soc-card";

                const proto = (row.flow_protocol_hint || "unknown").toLowerCase();
                const displayProto = proto === "tls" ? "HTTPS (TLS)" : proto === "http" ? "HTTP" : proto === "ssh" ? "SSH" : proto === "smb" ? "SMB" : proto.toUpperCase();

                const detectSource = row.flow_http_detect_source || row.flow_tls_detect_source || row.flow_ssh_detect_source || row.flow_smb_detect_source || "unknown";

                let evidenceHtml = "";

                if (proto === "http") {
                    evidenceHtml = `
                        <div class="soc-evidence-grid">
                            <div><span>Method</span><strong>${row.flow_http_method || "N/A"}</strong></div>
                            <div><span>Host</span><strong>${row.flow_http_host || "N/A"}</strong></div>
                            <div class="full"><span>Path</span><strong>${row.flow_http_path || "N/A"}</strong></div>
                        </div>
                    `;
                } else if (proto === "tls") {
                    evidenceHtml = `
                        <div class="soc-evidence-grid">
                            <div class="full"><span>TLS SNI</span><strong>${row.flow_tls_sni || "N/A"}</strong></div>
                        </div>
                    `;
                } else if (proto === "ssh") {
                    evidenceHtml = `
                        <div class="soc-evidence-grid">
                            <div class="full"><span>SSH Banner</span><strong>${row.flow_ssh_banner || "N/A"}</strong></div>
                        </div>
                    `;
                } else if (proto === "smb") {
                    evidenceHtml = `
                        <div class="soc-evidence-grid">
                            <div><span>SMB Version</span><strong>${row.flow_smb_version || "N/A"}</strong></div>
                        </div>
                    `;
                }

                card.innerHTML = `
                    <div class="soc-card-top">
                        <div class="soc-title-wrap">
                            <div class="soc-proto">${displayProto}</div>
                            <div class="soc-flow">${row.flow_src_ip}:${row.flow_src_port} → ${row.flow_dst_ip}:${row.flow_dst_port}</div>
                        </div>
                        <div class="soc-badge-group">
                            ${severityBadge(row.flow_risk_level)}
                            ${sourceBadge(detectSource)}
                        </div>
                    </div>

                    <div class="soc-score-row">
                        <span>Risk Score</span>
                        <strong>${row.flow_risk_score ?? "N/A"}</strong>
                    </div>

                    ${evidenceHtml}

                    <div class="soc-summary">
                        ${buildSummary(row, proto)}
                    </div>
                `;

                grid.appendChild(card);
            });

            const totalPages = Math.ceil(json.total / json.per_page);
            renderPagination("#protocol-pagination", json.page, totalPages, loadProtocolPage);
        })
        .catch((error) => {
            const grid = document.getElementById("protocol-grid");
            grid.innerHTML = "";
            grid.classList.add("single-col");

            grid.innerHTML = `<div class="muted no-data-msg">Failed to load protocol evidence: ${error.message}</div>`;
            renderPagination("#protocol-pagination", 1, 1, loadProtocolPage);
        });
}

function buildNoDataMessage(protocol, detectSource) {
    let protocolLabel = "";

    if (protocol === "ssh") protocolLabel = "SSH ";
    else if (protocol === "http") protocolLabel = "HTTP ";
    else if (protocol === "tls") protocolLabel = "HTTPS (TLS) ";
    else if (protocol === "smb") protocolLabel = "SMB ";

    let message = `No ${protocolLabel}protocol evidence found`;

    if (detectSource === "payload") {
        message += " under (Payload-Based)";
    } else if (detectSource === "port") {
        message += " under (Port-Based)";
    }

    message += ".";

    return message;
}

function renderPagination(containerSelector, currentPage, totalPages, onPageClick) {
    const pagination = document.querySelector(containerSelector);

    if (!pagination) {
        return;
    }

    pagination.innerHTML = "";

    if (totalPages <= 1) {
        return;
    }

    const createBtn = (text, page, disabled = false, active = false) => {
        const btn = document.createElement("button");
        btn.textContent = text;
        btn.className = "page-btn";

        if (active) btn.classList.add("active");
        if (disabled) btn.disabled = true;

        btn.addEventListener("click", () => onPageClick(page));
        return btn;
    };

    pagination.appendChild(createBtn("«", currentPage - 1, currentPage === 1));

    const range = 2;
    let start = Math.max(1, currentPage - range);
    let end = Math.min(totalPages, currentPage + range);

    if (start > 1) {
        pagination.appendChild(createBtn("1", 1));
        if (start > 2) {
            const dots = document.createElement("span");
            dots.textContent = "...";
            dots.className = "pagination-dots";
            pagination.appendChild(dots);
        }
    }

    for (let p = start; p <= end; p++) {
        pagination.appendChild(createBtn(p, p, false, p === currentPage));
    }

    if (end < totalPages) {
        if (end < totalPages - 1) {
            const dots = document.createElement("span");
            dots.textContent = "...";
            dots.className = "pagination-dots";
            pagination.appendChild(dots);
        }
        pagination.appendChild(createBtn(totalPages, totalPages));
    }

    pagination.appendChild(createBtn("»", currentPage + 1, currentPage === totalPages));
}

function updateProtocolTitle(protocol, detectSource = "all") {
    let protocolLabel = "All";

    if (protocol === "ssh") protocolLabel = "SSH";
    else if (protocol === "http") protocolLabel = "HTTP";
    else if (protocol === "tls") protocolLabel = "HTTPS (TLS)";
    else if (protocol === "smb") protocolLabel = "SMB";

    let title = `${protocolLabel} Protocol Evidence Summary`;

    if (detectSource === "payload") {
        title += " (Payload-Based)";
    } else if (detectSource === "port") {
        title += " (Port-Based)";
    }

    const titleEl = document.getElementById("protocol-title");
    if (titleEl) {
        titleEl.textContent = title;
    }
}

function exportProtocolEvidence() {
    const protocol = document.getElementById("protocol-filter")?.value || "all";
    const detectSource = document.getElementById("detect-source-filter")?.value || "all";
    const riskSort = document.getElementById("risk-sort-filter")?.value || "desc";

    const url =
        `/api/export/protocol-evidence?protocol=${encodeURIComponent(protocol)}` +
        `&detect_source=${encodeURIComponent(detectSource)}` +
        `&risk_sort=${encodeURIComponent(riskSort)}`;

    window.location.href = url;
}

document.addEventListener("DOMContentLoaded", () => {
    const exportProtocolBtn = document.getElementById("export-protocol-btn");

    if (exportProtocolBtn) {
        exportProtocolBtn.addEventListener("click", exportProtocolEvidence);
    }
});

document.addEventListener("DOMContentLoaded", () => {
    loadPage(1);
    loadFlowPage(1);
    loadProtocolPage(1);

    const protocolFilter = document.getElementById("protocol-filter");
    const detectSourceFilter = document.getElementById("detect-source-filter");
    const riskSortFilter = document.getElementById("risk-sort-filter");

    if (protocolFilter) {
        protocolFilter.addEventListener("change", () => {
            loadProtocolPage(1);
        });
    }

    if (detectSourceFilter) {
        detectSourceFilter.addEventListener("change", () => {
            loadProtocolPage(1);
        });
    }

    if (riskSortFilter) {
        riskSortFilter.addEventListener("change", () => {
            loadProtocolPage(1);
        });
    }
});
