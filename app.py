"""
CallShield - AI 실시간 보이스피싱 탐지 서비스 (MVP 데모)
Streamlit 기반 인터랙티브 데모
"""
import streamlit as st
import time
from detector import CallShieldDetector, DEMO_SCENARIOS, SPAM_DB

# ============================================================
# 페이지 설정
# ============================================================
st.set_page_config(
    page_title="CallShield - AI 보이스피싱 탐지",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# 커스텀 CSS
# ============================================================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Noto+Sans+KR:wght@300;400;500;700;900&display=swap');

/* 전체 앱 */
.stApp {
    font-family: 'Noto Sans KR', sans-serif;
}

/* 헤더 영역 */
.main-header {
    background: linear-gradient(135deg, #0F172A 0%, #1E293B 50%, #0F172A 100%);
    border-radius: 16px;
    padding: 2rem 2.5rem;
    margin-bottom: 1.5rem;
    border: 1px solid #334155;
    position: relative;
    overflow: hidden;
}
.main-header::before {
    content: '';
    position: absolute;
    top: -50%;
    right: -20%;
    width: 400px;
    height: 400px;
    background: radial-gradient(circle, rgba(59,130,246,0.15) 0%, transparent 70%);
    pointer-events: none;
}
.main-header h1 {
    color: #F8FAFC;
    font-size: 2rem;
    font-weight: 900;
    margin: 0 0 0.3rem 0;
    letter-spacing: -0.5px;
}
.main-header p {
    color: #94A3B8;
    font-size: 1rem;
    margin: 0;
    font-weight: 300;
}
.shield-icon {
    font-size: 2.5rem;
    margin-right: 0.8rem;
}

/* 위험도 미터 */
.risk-meter {
    background: #0F172A;
    border-radius: 16px;
    padding: 1.5rem;
    border: 1px solid #334155;
    text-align: center;
    margin-bottom: 1rem;
}
.risk-score {
    font-size: 4rem;
    font-weight: 900;
    line-height: 1;
    margin: 0.5rem 0;
}
.risk-label {
    font-size: 1.1rem;
    font-weight: 700;
    margin: 0.5rem 0;
}
.risk-action {
    font-size: 0.85rem;
    color: #94A3B8;
    margin-top: 0.3rem;
}

/* 프로그레스 바 */
.risk-bar-container {
    background: #1E293B;
    border-radius: 99px;
    height: 12px;
    margin: 1rem 0;
    overflow: hidden;
}
.risk-bar {
    height: 100%;
    border-radius: 99px;
    transition: width 0.5s ease;
}

/* 대화 메시지 */
.chat-message {
    padding: 1rem 1.2rem;
    border-radius: 12px;
    margin-bottom: 0.8rem;
    font-size: 0.95rem;
    line-height: 1.6;
}
.chat-caller {
    background: #1E293B;
    border: 1px solid #334155;
    color: #E2E8F0;
    border-left: 4px solid #64748B;
}
.chat-caller .chat-label {
    color: #94A3B8;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 0.3rem;
}

/* 경고 카드 */
.alert-card {
    border-radius: 12px;
    padding: 1rem 1.2rem;
    margin-bottom: 0.6rem;
    font-size: 0.9rem;
    line-height: 1.5;
}
.alert-critical {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.3);
    color: #FCA5A5;
}
.alert-warning {
    background: rgba(245, 158, 11, 0.1);
    border: 1px solid rgba(245, 158, 11, 0.3);
    color: #FCD34D;
}
.alert-info {
    background: rgba(59, 130, 246, 0.1);
    border: 1px solid rgba(59, 130, 246, 0.3);
    color: #93C5FD;
}
.alert-safe {
    background: rgba(34, 197, 94, 0.1);
    border: 1px solid rgba(34, 197, 94, 0.3);
    color: #86EFAC;
}

/* 공식 절차 근거 */
.procedure-card {
    background: rgba(59, 130, 246, 0.08);
    border: 1px solid rgba(59, 130, 246, 0.2);
    border-radius: 10px;
    padding: 0.8rem 1rem;
    margin-bottom: 0.5rem;
    font-size: 0.85rem;
    color: #93C5FD;
    line-height: 1.5;
}
.procedure-card::before {
    content: '📋 ';
}

/* 패턴 태그 */
.pattern-tag {
    display: inline-block;
    padding: 0.3rem 0.8rem;
    border-radius: 99px;
    font-size: 0.8rem;
    font-weight: 600;
    margin: 0.2rem;
}
.tag-institution { background: rgba(139, 92, 246, 0.2); color: #C4B5FD; border: 1px solid rgba(139, 92, 246, 0.3); }
.tag-fear { background: rgba(239, 68, 68, 0.2); color: #FCA5A5; border: 1px solid rgba(239, 68, 68, 0.3); }
.tag-money { background: rgba(245, 158, 11, 0.2); color: #FCD34D; border: 1px solid rgba(245, 158, 11, 0.3); }
.tag-privacy { background: rgba(236, 72, 153, 0.2); color: #F9A8D4; border: 1px solid rgba(236, 72, 153, 0.3); }
.tag-app { background: rgba(20, 184, 166, 0.2); color: #5EEAD4; border: 1px solid rgba(20, 184, 166, 0.3); }

/* 번호 조회 결과 */
.number-result {
    border-radius: 12px;
    padding: 1.2rem;
    margin: 1rem 0;
}
.number-safe {
    background: rgba(34, 197, 94, 0.1);
    border: 1px solid rgba(34, 197, 94, 0.3);
}
.number-danger {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.3);
}

/* 사이드바 스타일 */
section[data-testid="stSidebar"] {
    background: #0F172A;
}

/* 버튼 */
.stButton > button {
    border-radius: 10px;
    font-weight: 600;
    font-family: 'Noto Sans KR', sans-serif;
}

/* 탭 */
.stTabs [data-baseweb="tab-list"] {
    gap: 0.5rem;
}
.stTabs [data-baseweb="tab"] {
    border-radius: 10px;
    font-family: 'Noto Sans KR', sans-serif;
}

/* 구분선 */
.divider {
    border: none;
    border-top: 1px solid #334155;
    margin: 1.5rem 0;
}
</style>
""", unsafe_allow_html=True)


# ============================================================
# 세션 상태 초기화
# ============================================================
if "detector" not in st.session_state:
    st.session_state.detector = CallShieldDetector()
if "analysis_history" not in st.session_state:
    st.session_state.analysis_history = []
if "demo_step" not in st.session_state:
    st.session_state.demo_step = 0
if "current_scenario" not in st.session_state:
    st.session_state.current_scenario = None


# ============================================================
# 헤더
# ============================================================
st.markdown("""
<div class="main-header">
    <div style="display:flex; align-items:center;">
        <span class="shield-icon">🛡️</span>
        <div>
            <h1>CallShield</h1>
            <p>AI 실시간 보이스피싱 탐지 서비스 · MVP 데모</p>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)


# ============================================================
# 사이드바
# ============================================================
with st.sidebar:
    st.markdown("### 🎯 기능 선택")
    mode = st.radio(
        "모드를 선택하세요",
        ["📞 실시간 통화 분석", "🔍 번호 조회", "📖 서비스 소개"],
        label_visibility="collapsed",
    )

    st.markdown("<hr class='divider'>", unsafe_allow_html=True)

    if mode == "📞 실시간 통화 분석":
        st.markdown("### 🎭 데모 시나리오")
        st.caption("프리셋 시나리오를 선택하면 한 문장씩 자동 입력됩니다.")

        scenario_choice = st.selectbox(
            "시나리오 선택",
            ["직접 입력"] + list(DEMO_SCENARIOS.keys()),
            label_visibility="collapsed",
        )

        if scenario_choice != "직접 입력":
            if st.button("▶️ 시나리오 시작", use_container_width=True):
                st.session_state.detector = CallShieldDetector()
                st.session_state.analysis_history = []
                st.session_state.demo_step = 0
                st.session_state.current_scenario = scenario_choice

            if st.session_state.current_scenario == scenario_choice:
                scenario_msgs = DEMO_SCENARIOS[scenario_choice]
                step = st.session_state.demo_step
                if step < len(scenario_msgs):
                    if st.button(f"📨 다음 발화 ({step+1}/{len(scenario_msgs)})", use_container_width=True):
                        msg = scenario_msgs[step]
                        result = st.session_state.detector.analyze_message(msg)
                        st.session_state.analysis_history.append(result)
                        st.session_state.demo_step += 1
                        st.rerun()
                else:
                    st.success("✅ 시나리오 완료!")

        st.markdown("<hr class='divider'>", unsafe_allow_html=True)

        if st.button("🔄 대화 초기화", use_container_width=True):
            st.session_state.detector = CallShieldDetector()
            st.session_state.analysis_history = []
            st.session_state.demo_step = 0
            st.session_state.current_scenario = None
            st.rerun()

    st.markdown("<hr class='divider'>", unsafe_allow_html=True)
    st.markdown(
        "<div style='text-align:center; color:#64748B; font-size:0.75rem;'>"
        "CallShield MVP Demo v1.0<br>"
        "피싱·스캠 예방을 위한 서비스 개발 경진대회"
        "</div>",
        unsafe_allow_html=True,
    )


# ============================================================
# 메인: 실시간 통화 분석
# ============================================================
if mode == "📞 실시간 통화 분석":
    col_chat, col_analysis = st.columns([3, 2])

    # --- 왼쪽: 대화 영역 ---
    with col_chat:
        st.markdown("#### 💬 통화 내용")

        # 직접 입력 모드
        if (st.session_state.current_scenario is None or
                st.session_state.current_scenario not in DEMO_SCENARIOS):
            with st.form("input_form", clear_on_submit=True):
                user_input = st.text_input(
                    "상대방 발화를 입력하세요",
                    placeholder="예: 서울중앙지검 수사관입니다...",
                    label_visibility="collapsed",
                )
                submitted = st.form_submit_button("분석 📡", use_container_width=True)
                if submitted and user_input.strip():
                    result = st.session_state.detector.analyze_message(user_input.strip())
                    st.session_state.analysis_history.append(result)
                    st.rerun()

        # 대화 기록 표시
        if not st.session_state.analysis_history:
            st.markdown(
                "<div style='text-align:center; padding:3rem; color:#64748B;'>"
                "📱 통화가 시작되지 않았습니다.<br>"
                "<span style='font-size:0.85rem;'>왼쪽 사이드바에서 시나리오를 선택하거나, 직접 상대방 발화를 입력하세요.</span>"
                "</div>",
                unsafe_allow_html=True,
            )
        else:
            for i, result in enumerate(st.session_state.analysis_history):
                # 상대방 발화
                st.markdown(
                    f"<div class='chat-message chat-caller'>"
                    f"<div class='chat-label'>상대방 ({i+1}번째 발화)</div>"
                    f"{result['message']}"
                    f"</div>",
                    unsafe_allow_html=True,
                )

                # 새로 감지된 패턴 알림
                for det in result["new_detections"]:
                    risk = result["risk_level"]
                    alert_class = "alert-critical" if result["risk_score"] >= 80 else \
                                  "alert-warning" if result["risk_score"] >= 50 else "alert-info"
                    st.markdown(
                        f"<div class='alert-card {alert_class}'>"
                        f"{det['label']} 감지 — <b>\"{det['keyword']}\"</b><br>"
                        f"<span style='font-size:0.8rem;'>{det['description']}</span>"
                        f"</div>",
                        unsafe_allow_html=True,
                    )

                # 새로 제시된 공식 절차 근거
                for proc in result["new_procedures"]:
                    st.markdown(
                        f"<div class='procedure-card'>{proc}</div>",
                        unsafe_allow_html=True,
                    )

            # 위험도 80% 이상이면 최종 경고
            summary = st.session_state.detector.get_summary()
            if summary["risk_score"] >= 80:
                st.markdown(
                    "<div class='alert-card alert-critical' style='margin-top:1rem; padding:1.5rem; text-align:center;'>"
                    "<div style='font-size:2rem; margin-bottom:0.5rem;'>🚨</div>"
                    "<div style='font-size:1.2rem; font-weight:900;'>보이스피싱 확정 — 즉시 통화를 종료하세요!</div>"
                    "<div style='font-size:0.85rem; margin-top:0.5rem;'>절대 개인정보를 알려주지 마시고, "
                    "경찰(112) 또는 금감원(1332)에 즉시 신고하세요.</div>"
                    "</div>",
                    unsafe_allow_html=True,
                )

    # --- 오른쪽: 분석 대시보드 ---
    with col_analysis:
        summary = st.session_state.detector.get_summary()
        risk = summary["risk_level"]

        # 위험도 미터
        color_map = {
            "critical": "#EF4444",
            "high": "#F59E0B",
            "caution": "#EAB308",
            "safe": "#22C55E",
        }
        bar_color = color_map.get(risk["level"], "#22C55E")

        st.markdown(
            f"<div class='risk-meter'>"
            f"<div style='font-size:0.8rem; color:#64748B; font-weight:600; letter-spacing:1px;'>실시간 위험도</div>"
            f"<div class='risk-score' style='color:{bar_color};'>{summary['risk_score']}%</div>"
            f"<div class='risk-bar-container'>"
            f"<div class='risk-bar' style='width:{summary['risk_score']}%; background:{bar_color};'></div>"
            f"</div>"
            f"<div class='risk-label' style='color:{bar_color};'>{risk['emoji']} {risk['label']}</div>"
            f"<div class='risk-action'>{risk['action']}</div>"
            f"</div>",
            unsafe_allow_html=True,
        )

        # 감지된 패턴 태그
        st.markdown("#### 🔎 감지된 패턴")
        if summary["detected_categories"]:
            tag_class_map = {
                "기관사칭": "tag-institution",
                "공포유발": "tag-fear",
                "금전요구": "tag-money",
                "개인정보탈취": "tag-privacy",
                "앱설치유도": "tag-app",
            }
            from detector import PHISHING_PATTERNS
            tags_html = ""
            for cat in summary["detected_categories"]:
                tag_cls = tag_class_map.get(cat, "tag-institution")
                label = PHISHING_PATTERNS[cat]["label"]
                count = len(summary["detected_keywords"].get(cat, []))
                tags_html += f"<span class='pattern-tag {tag_cls}'>{label} ({count}건)</span> "
            st.markdown(tags_html, unsafe_allow_html=True)

            # 감지 키워드 상세
            with st.expander("감지된 키워드 상세"):
                for cat, keywords in summary["detected_keywords"].items():
                    label = PHISHING_PATTERNS[cat]["label"]
                    st.markdown(f"**{label}**: {', '.join(keywords)}")
        else:
            st.markdown(
                "<div style='color:#64748B; font-size:0.9rem; padding:1rem 0;'>"
                "감지된 패턴이 없습니다.</div>",
                unsafe_allow_html=True,
            )

        # 공식 절차 근거 목록
        st.markdown("#### 📋 공식 절차 근거")
        if summary["official_procedures"]:
            for proc in summary["official_procedures"]:
                st.markdown(
                    f"<div class='procedure-card'>{proc}</div>",
                    unsafe_allow_html=True,
                )
        else:
            st.markdown(
                "<div style='color:#64748B; font-size:0.9rem; padding:1rem 0;'>"
                "해당되는 공식 절차 근거가 없습니다.</div>",
                unsafe_allow_html=True,
            )

        # 신고 버튼
        if summary["risk_score"] >= 50:
            st.markdown("<hr class='divider'>", unsafe_allow_html=True)
            st.markdown("#### 🚔 긴급 신고")
            c1, c2 = st.columns(2)
            with c1:
                st.markdown(
                    "<div style='background:rgba(239,68,68,0.15); border:1px solid rgba(239,68,68,0.3); "
                    "border-radius:10px; padding:1rem; text-align:center;'>"
                    "<div style='font-size:1.5rem;'>🚨</div>"
                    "<div style='color:#FCA5A5; font-weight:700;'>경찰 112</div>"
                    "<div style='color:#94A3B8; font-size:0.75rem;'>보이스피싱 신고</div>"
                    "</div>",
                    unsafe_allow_html=True,
                )
            with c2:
                st.markdown(
                    "<div style='background:rgba(59,130,246,0.15); border:1px solid rgba(59,130,246,0.3); "
                    "border-radius:10px; padding:1rem; text-align:center;'>"
                    "<div style='font-size:1.5rem;'>📞</div>"
                    "<div style='color:#93C5FD; font-weight:700;'>금감원 1332</div>"
                    "<div style='color:#94A3B8; font-size:0.75rem;'>피해 상담·신고</div>"
                    "</div>",
                    unsafe_allow_html=True,
                )


# ============================================================
# 메인: 번호 조회
# ============================================================
elif mode == "🔍 번호 조회":
    st.markdown("#### 🔍 수신 번호 조회 (1단계 방어)")
    st.caption("전화번호를 입력하면 스팸·피싱 DB에서 위험 여부를 조회합니다.")

    col1, col2 = st.columns([2, 1])
    with col1:
        phone_input = st.text_input(
            "전화번호 입력",
            placeholder="예: 02-1234-5678",
            label_visibility="collapsed",
        )
    with col2:
        search_btn = st.button("조회 🔎", use_container_width=True)

    if search_btn and phone_input.strip():
        result = st.session_state.detector.check_number(phone_input.strip())
        if result:
            st.markdown(
                f"<div class='number-result number-danger'>"
                f"<div style='font-size:1.5rem; margin-bottom:0.5rem;'>⚠️ 위험 번호</div>"
                f"<div style='color:#FCA5A5; font-size:1.1rem; font-weight:700;'>{phone_input}</div>"
                f"<div style='margin-top:0.8rem; color:#E2E8F0;'>"
                f"<b>분류:</b> {result['category']}<br>"
                f"<b>신고 건수:</b> {result['reports']}건<br>"
                f"<b>최근 신고:</b> {result['last_report']}"
                f"</div>"
                f"<div style='margin-top:1rem; color:#FCA5A5; font-weight:600;'>"
                f"💡 이 번호의 전화를 받지 않는 것을 권장합니다.</div>"
                f"</div>",
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f"<div class='number-result number-safe'>"
                f"<div style='font-size:1.5rem; margin-bottom:0.5rem;'>✅ DB 미등록 번호</div>"
                f"<div style='color:#86EFAC; font-size:1.1rem; font-weight:700;'>{phone_input}</div>"
                f"<div style='margin-top:0.8rem; color:#E2E8F0;'>"
                f"스팸·피싱 DB에 등록되지 않은 번호입니다.<br>"
                f"다만, 신규 번호일 수 있으므로 통화 시 <b>2단계 AI 실시간 분석</b>을 활용하세요."
                f"</div>"
                f"</div>",
                unsafe_allow_html=True,
            )

    # 샘플 DB 안내
    with st.expander("📂 테스트용 샘플 번호 DB"):
        for num, info in SPAM_DB.items():
            st.markdown(f"- `{num}` → {info['category']} (신고 {info['reports']}건)")


# ============================================================
# 메인: 서비스 소개
# ============================================================
elif mode == "📖 서비스 소개":
    st.markdown("#### 📖 CallShield 서비스 소개")

    st.markdown("""
    **CallShield**는 사용자의 실시간 통화 내용을 AI가 분석하여 보이스피싱을 탐지하고,
    **"왜 이 전화가 피싱인지"를 공식 기관 대응 절차 근거와 함께 알려주는** 서비스입니다.
    """)

    st.markdown("<hr class='divider'>", unsafe_allow_html=True)

    # 2단계 방어 체계
    st.markdown("##### 🛡️ 2단계 방어 체계")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown(
            "<div style='background:#0F172A; border:1px solid #334155; border-radius:12px; padding:1.5rem;'>"
            "<div style='font-size:1.5rem; margin-bottom:0.5rem;'>1️⃣</div>"
            "<div style='color:#E2E8F0; font-weight:700; font-size:1.05rem; margin-bottom:0.5rem;'>수신 번호 조회</div>"
            "<div style='color:#94A3B8; font-size:0.9rem; line-height:1.6;'>"
            "전화 수신 시 스팸·피싱 DB를 즉시 조회하여<br>"
            "위험 번호의 카테고리와 신고 이력을 표시합니다."
            "</div></div>",
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            "<div style='background:#0F172A; border:1px solid #334155; border-radius:12px; padding:1.5rem;'>"
            "<div style='font-size:1.5rem; margin-bottom:0.5rem;'>2️⃣</div>"
            "<div style='color:#E2E8F0; font-weight:700; font-size:1.05rem; margin-bottom:0.5rem;'>AI 실시간 분석</div>"
            "<div style='color:#94A3B8; font-size:0.9rem; line-height:1.6;'>"
            "통화 중 대화를 실시간 분석하여 피싱 패턴을 감지하고<br>"
            "공식 절차 근거를 제시하여 사용자를 보호합니다."
            "</div></div>",
            unsafe_allow_html=True,
        )

    st.markdown("<hr class='divider'>", unsafe_allow_html=True)

    # 5가지 탐지 패턴
    st.markdown("##### 🔎 5가지 피싱 패턴 탐지")
    patterns_info = [
        ("🏛️ 기관 사칭", "검찰·금감원·경찰 등 공공기관을 사칭", "tag-institution"),
        ("😨 공포·위기감 조성", "체포영장, 계좌동결 등으로 공포심 유발", "tag-fear"),
        ("💰 금전 요구", "안전계좌 이체, 보증금 등 금전 요구", "tag-money"),
        ("🔓 개인정보 탈취", "주민번호, 계좌번호 등 민감정보 요구", "tag-privacy"),
        ("📱 앱 설치 유도", "원격제어 앱, 악성 링크 설치 유도", "tag-app"),
    ]
    tags = ""
    for label, desc, cls in patterns_info:
        tags += (
            f"<div style='display:inline-block; margin:0.3rem;'>"
            f"<span class='pattern-tag {cls}' style='font-size:0.85rem;'>{label}</span>"
            f"<span style='color:#94A3B8; font-size:0.8rem; margin-left:0.3rem;'>{desc}</span>"
            f"</div><br>"
        )
    st.markdown(tags, unsafe_allow_html=True)

    st.markdown("<hr class='divider'>", unsafe_allow_html=True)

    # 핵심 차별점
    st.markdown("##### ⭐ 핵심 차별점: 공식 절차 근거 대비")
    st.markdown(
        "<div style='background:rgba(59,130,246,0.08); border:1px solid rgba(59,130,246,0.2); "
        "border-radius:12px; padding:1.5rem; line-height:1.8; color:#CBD5E1;'>"
        "기존 스팸 차단 앱은 <b>'이 번호는 스팸입니다'</b>라고만 알려줍니다.<br><br>"
        "CallShield는 <b>'왜 이 전화가 피싱인지'</b>를 구체적 근거와 함께 알려줍니다.<br><br>"
        "예시: <i style='color:#93C5FD;'>\"금감원은 전화로 자금 이체를 요구하지 않습니다. "
        "현재 상대방은 금감원을 사칭하며 안전계좌 이체를 요구하고 있어 보이스피싱으로 판단됩니다.\"</i><br><br>"
        "이를 통해 심리적으로 압도된 상태에서도 사용자가 <b>스스로 냉정한 판단</b>을 내릴 수 있도록 돕습니다."
        "</div>",
        unsafe_allow_html=True,
    )

    st.markdown("<hr class='divider'>", unsafe_allow_html=True)
    st.markdown(
        "<div style='text-align:center; color:#64748B; font-size:0.85rem; padding:1rem;'>"
        "📌 왼쪽 사이드바에서 <b>📞 실시간 통화 분석</b>을 선택하여 직접 체험해보세요!"
        "</div>",
        unsafe_allow_html=True,
    )
