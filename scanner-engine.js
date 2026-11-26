const WORKER_ENDPOINT = "https://cyberguard-scanner.thienndh-26ns.workers.dev";
// Danh sách tên miền chính thống tại Việt Nam để phát hiện giả mạo (Typosquatting)
const OFFICIAL_DOMAINS = [
  "vietcombank.com.vn", "techcombank.com", "bidv.com.vn", "vietinbank.vn",
  "mbbank.com.vn", "agribank.com.vn", "vpbank.com.vn", "acb.com.vn",
  "dichvucong.gov.vn", "vneid.gov.vn", "gdt.gov.vn", "baohiemxahoi.gov.vn",
  "momo.vn", "zalopay.vn", "shopee.vn", "lazada.vn"
];

// 1. Thuật toán Levenshtein Distance đo độ tương đồng chuỗi
function levenshteinDistance(a, b) {
  const matrix = Array.from({ length: a.length + 1 }, () => Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) matrix[i][0] = i;
  for (let j = 0; j <= b.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost
      );
    }
  }
  return matrix[a.length][b.length];
}

// 2. Tính Shannon Entropy phát hiện tên miền sinh tự động bởi mã độc (DGA)
function calculateShannonEntropy(str) {
  const len = str.length;
  const freq = {};
  for (const char of str) freq[char] = (freq[char] || 0) + 1;
  return Object.values(freq).reduce((sum, f) => {
    const p = f / len;
    return sum - p * Math.log2(p);
  }, 0);
}

// 3. Phân tích Heuristic cục bộ trước khi gửi lên Cloud
function analyzeUrlLocal(rawUrl) {
  const findings = [];
  let localScore = 0;

  try {
    const normalized = rawUrl.startsWith("http") ? rawUrl : `https://${rawUrl}`;
    const urlObj = new URL(normalized);
    const hostname = urlObj.hostname.toLowerCase().replace(/^www\./, "");

    // Kiểm tra IP trần
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      localScore += 45;
      findings.push("Sử dụng địa chỉ IP trực tiếp thay vì tên miền hợp pháp.");
    }

    // Kiểm tra từ khóa nhạy cảm kết hợp tên miền lạ
    const brandKeywords = ["vietcombank", "vneid", "dichvucong", "bidv", "mbbank", "techcombank", "momo", "cong-an"];
    const isOfficial = OFFICIAL_DOMAINS.includes(hostname);

    if (!isOfficial) {
      for (const kw of brandKeywords) {
        if (hostname.includes(kw)) {
          localScore += 50;
          findings.push(`Tên miền chứa từ khóa thương hiệu "${kw}" nhưng không thuộc hệ thống chính thống.`);
        }
      }

      // Kiểm tra giả mạo ký tự gần giống (Levenshtein <= 2)
      for (const official of OFFICIAL_DOMAINS) {
        const dist = levenshteinDistance(hostname, official);
        if (dist > 0 && dist <= 2) {
          localScore += 55;
          findings.push(`Nghi vấn giả mạo tên miền chính thức "${official}" (sai khác ${dist} ký tự).`);
        }
      }
    }

    // Kiểm tra Entropy tên miền chính
    const domainLabel = hostname.split(".")[0];
    const entropy = calculateShannonEntropy(domainLabel);
    if (domainLabel.length >= 10 && entropy > 3.6) {
      localScore += 25;
      findings.push(`Độ hỗn loạn ký tự cao (Entropy = ${entropy.toFixed(2)}), dấu hiệu tên miền tạo tự động bởi mã độc.`);
    }

    // Kiểm tra đường dẫn tải trực tiếp file thực thi
    if (/\.(apk|exe|bat|scr|msi|vbs)(\?.*)?$/i.test(urlObj.pathname)) {
      localScore += 60;
      findings.push("Liên kết trỏ trực tiếp tới tệp cài đặt thực thi nguy hiểm (.apk/.exe).");
    }

    return { localScore, findings, entropy: entropy.toFixed(2), isOfficial };
  } catch {
    return { localScore: 20, findings: ["Định dạng URL không hợp lệ."], entropy: "0", isOfficial: false };
  }
}

// 4. Hàm chính: Quét URL toàn diện (Kết hợp Local Heuristic + Cloud Threat Intel)
async function scanUrlDeep(inputUrl) {
  const local = analyzeUrlLocal(inputUrl);
  
  const res = await fetch(WORKER_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type: "url", target: inputUrl })
  });
  const cloud = await res.json();

  let totalRisk = local.localScore;
  const reasons = [...local.findings];

  if (cloud.gsbThreats && cloud.gsbThreats.length > 0) {
    totalRisk = 100;
    reasons.unshift(`Google Safe Browsing cảnh báo: ${cloud.gsbThreats[0].threatType}`);
  }

  if (cloud.vtMalicious > 0) {
    totalRisk = Math.max(totalRisk, Math.min(100, 60 + cloud.vtMalicious * 10));
    reasons.unshift(`${cloud.vtMalicious}/${cloud.vtTotal} trình diệt virus quốc tế đánh dấu độc hại.`);
  }

  if (cloud.domainAgeDays !== null && cloud.domainAgeDays < 30 && !local.isOfficial) {
    totalRisk += 30;
    reasons.push(`Tên miền mới đăng ký chỉ ${cloud.domainAgeDays} ngày trước (Rủi ro cao).`);
  }

  if (cloud.redirected && cloud.finalUrl !== inputUrl) {
    reasons.push(`Liên kết chuyển hướng ngầm tới: ${cloud.finalUrl}`);
  }

  totalRisk = Math.min(100, totalRisk);

  return {
    riskScore: totalRisk,
    verdict: totalRisk >= 70 ? "NGUY HIỂM CAO" : totalRisk >= 35 ? "CẦN CẢNH GIÁC" : "AN TOÀN",
    reasons: reasons.length > 0 ? reasons : ["Không phát hiện dấu hiệu mã độc hay giả mạo trên các cơ sở dữ liệu."],
    metrics: {
      vtDetections: `${cloud.vtMalicious || 0}/${cloud.vtTotal || 0}`,
      domainAge: cloud.domainAgeDays !== null ? `${cloud.domainAgeDays} ngày` : "Không rõ",
      entropy: local.entropy,
      finalUrl: cloud.finalUrl
    }
  };
}

// 5. Hàm quét Virus tệp tin bằng mã băm SHA-256 (Không tải file lên server)
async function scanFileByHash(file) {
  // Đọc file và tính SHA-256 ngay trên trình duyệt người dùng
  const arrayBuffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest("SHA-256", arrayBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const sha256Hex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");

  const res = await fetch(WORKER_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type: "hash", target: sha256Hex })
  });
  const cloud = await res.json();

  return {
    fileName: file.name,
    fileSizeKB: (file.size / 1024).toFixed(1),
    sha256: sha256Hex,
    ...cloud
  };
}
