// hooks/apiConfig.js
// 백엔드 주소 자동 감지
// - 개발 환경 (localhost): localhost:8000
// - 운영 환경 (서버 IP 접속): 같은 IP의 8000 포트 자동 사용

const hostname = window.location.hostname;

export const API_BASE =
  hostname === "localhost" || hostname === "127.0.0.1"
    ? "http://localhost:8000"
    : `http://${hostname}:8000`;

export default API_BASE;
