"""
CallShield 규칙 기반 보이스피싱 탐지 엔진
- 5가지 피싱 패턴 감지
- 기관별 공식 대응 절차 근거 제시
- 대화 누적 기반 위험도 산출
"""

# ============================================================
# 1. 피싱 패턴 정의 (5가지 카테고리)
# ============================================================
PHISHING_PATTERNS = {
    "기관사칭": {
        "keywords": [
            "검찰", "지검", "수사관", "수사부", "금융감독원", "금감원",
            "경찰청", "사이버수사", "국세청", "관세청", "국민건강보험",
            "건보공단", "은행 보안팀", "금융위원회", "법원", "대검찰청",
            "수사국", "형사부", "첨단범죄", "사이버범죄수사대",
            "보이스피싱 전담반", "금융범죄수사팀",
        ],
        "weight": 25,
        "label": "🏛️ 기관 사칭",
        "description": "수사기관·금융기관을 사칭하고 있습니다",
    },
    "공포유발": {
        "keywords": [
            "체포 영장", "구속 영장", "영장이 발부", "범죄에 연루",
            "대포통장", "자금세탁", "공범", "수배", "긴급 체포",
            "출국금지", "계좌가 동결", "압수수색", "형사처벌",
            "벌금", "구속", "고소", "고발", "범죄 수익",
            "당장 조치", "즉시 처리", "시간이 없", "오늘 안에",
            "지금 바로", "긴급", "비밀 유지", "아무에게도 말하지",
            "가족에게 알리면", "비밀리에",
        ],
        "weight": 25,
        "label": "😨 공포·위기감 조성",
        "description": "공포심을 유발하여 판단력을 흐리게 하고 있습니다",
    },
    "금전요구": {
        "keywords": [
            "안전계좌", "보호계좌", "국가 안전계좌", "자금 보호",
            "이체", "송금", "입금", "현금 인출", "현금 전달",
            "보증금", "예치금", "합의금", "과태료 납부",
            "세금 환급", "환급금", "미납 요금", "추가 납부",
            "가상계좌", "코인", "비트코인", "암호화폐",
            "대출 수수료", "선입금", "보험료",
        ],
        "weight": 30,
        "label": "💰 금전 요구",
        "description": "금전 이체·송금을 유도하고 있습니다",
    },
    "개인정보탈취": {
        "keywords": [
            "주민등록번호", "주민번호", "계좌번호", "카드번호",
            "비밀번호", "보안카드", "OTP", "인증번호",
            "본인확인", "본인 인증", "신분증", "신분증 사진",
            "공인인증서", "공동인증서", "계좌 비밀번호",
            "CVC", "유효기간", "카드 뒷면",
        ],
        "weight": 25,
        "label": "🔓 개인정보 탈취",
        "description": "민감한 개인정보·금융정보를 요구하고 있습니다",
    },
    "앱설치유도": {
        "keywords": [
            "앱 설치", "앱을 다운", "원격 제어", "원격 접속",
            "팀뷰어", "애니데스크", "보안 앱", "보안 프로그램",
            "악성코드 검사", "링크를 클릭", "URL 접속",
            "문자로 보낸 링크", "파일 다운로드", "APK",
        ],
        "weight": 20,
        "label": "📱 앱 설치·링크 유도",
        "description": "악성 앱 설치 또는 의심스러운 링크 접속을 유도하고 있습니다",
    },
}

# ============================================================
# 2. 기관별 공식 대응 절차 DB
# ============================================================
OFFICIAL_PROCEDURES = {
    "검찰": [
        "검찰은 전화로 수사 사실을 통보하지 않습니다 (대검찰청 공식 안내)",
        "검찰은 전화로 자금 이체·송금을 요구하지 않습니다",
        "검찰 수사관은 전화로 주민번호·계좌번호를 요구하지 않습니다",
        "체포영장·구속영장은 반드시 서면으로 제시됩니다 (형사소송법 제85조)",
    ],
    "지검": [
        "검찰은 전화로 수사 사실을 통보하지 않습니다 (대검찰청 공식 안내)",
        "검찰은 전화로 자금 이체·송금을 요구하지 않습니다",
        "체포영장·구속영장은 반드시 서면으로 제시됩니다 (형사소송법 제85조)",
    ],
    "금융감독원": [
        "금융감독원 직원은 개인에게 직접 전화하여 계좌정보를 요구하지 않습니다",
        "'금감원 안전계좌'는 존재하지 않는 제도입니다",
        "금감원은 전화로 자금 이체를 요구하지 않습니다",
    ],
    "금감원": [
        "금융감독원 직원은 개인에게 직접 전화하여 계좌정보를 요구하지 않습니다",
        "'금감원 안전계좌'는 존재하지 않는 제도입니다",
        "금감원은 전화로 자금 이체를 요구하지 않습니다",
    ],
    "경찰": [
        "경찰은 전화로 자금 이체를 요구하지 않습니다 (경찰청 공식 안내)",
        "경찰은 전화로 개인 금융정보(계좌번호, 비밀번호)를 요구하지 않습니다",
        "경찰 출석 요구는 반드시 서면(출석요구서)으로 이루어집니다",
    ],
    "경찰청": [
        "경찰은 전화로 자금 이체를 요구하지 않습니다 (경찰청 공식 안내)",
        "경찰은 전화로 개인 금융정보를 요구하지 않습니다",
    ],
    "국세청": [
        "국세청은 전화로 세금 납부를 요구하지 않습니다",
        "세금 고지는 반드시 서면(고지서)으로 발송됩니다",
        "국세청은 전화로 계좌번호·카드번호를 요구하지 않습니다",
    ],
    "건보공단": [
        "국민건강보험공단은 전화로 환급금 수령을 위한 계좌정보를 요구하지 않습니다",
        "환급금 안내는 공단 공식 앱 또는 서면으로 이루어집니다",
    ],
    "국민건강보험": [
        "국민건강보험공단은 전화로 환급금 수령을 위한 계좌정보를 요구하지 않습니다",
        "환급금 안내는 공단 공식 앱 또는 서면으로 이루어집니다",
    ],
    "은행": [
        "은행은 전화로 계좌 비밀번호·OTP 번호를 요구하지 않습니다",
        "은행은 전화로 보안카드 전체 번호를 요구하지 않습니다",
        "은행 보안팀이라며 원격 제어 앱 설치를 요구하는 것은 사기입니다",
    ],
    "안전계좌": [
        "'안전계좌', '보호계좌', '국가 안전계좌'는 존재하지 않는 제도입니다",
        "어떤 공공기관도 자금 보호를 위한 계좌 이체를 요구하지 않습니다",
    ],
    "법원": [
        "법원은 전화로 벌금·과태료 납부를 요구하지 않습니다",
        "영장 집행은 반드시 서면으로 이루어지며, 전화로 통보하지 않습니다",
    ],
}

# ============================================================
# 3. 스팸 번호 DB (시뮬레이션용 샘플)
# ============================================================
SPAM_DB = {
    "02-1234-5678": {"category": "대출 광고", "reports": 247, "last_report": "2025-02-06"},
    "1588-0000": {"category": "보험 영업", "reports": 312, "last_report": "2025-02-07"},
    "010-9876-5432": {"category": "피싱 신고", "reports": 89, "last_report": "2025-02-08"},
    "02-555-1234": {"category": "투자 사기", "reports": 156, "last_report": "2025-02-05"},
    "070-1234-5678": {"category": "스팸 광고", "reports": 523, "last_report": "2025-02-07"},
}


# ============================================================
# 4. 탐지 엔진 클래스
# ============================================================
class CallShieldDetector:
    def __init__(self):
        self.conversation = []       # 전체 대화 기록
        self.detected_patterns = {}  # 감지된 패턴: {카테고리: [매칭 키워드들]}
        self.risk_score = 0          # 현재 위험도 (0~100)
        self.alerts = []             # 경고 메시지 기록
        self.procedures = []         # 제시된 공식 절차 근거

    def check_number(self, phone_number: str) -> dict | None:
        """1단계: 번호 DB 조회"""
        return SPAM_DB.get(phone_number)

    def analyze_message(self, message: str) -> dict:
        """2단계: 대화 문장 분석 (핵심 기능)"""
        self.conversation.append(message)
        msg_lower = message.lower()

        new_detections = []
        new_procedures = []

        # 각 패턴 카테고리별로 키워드 매칭
        for category, pattern_info in PHISHING_PATTERNS.items():
            for keyword in pattern_info["keywords"]:
                if keyword in message:
                    # 새로운 감지 기록
                    if category not in self.detected_patterns:
                        self.detected_patterns[category] = []
                    if keyword not in self.detected_patterns[category]:
                        self.detected_patterns[category].append(keyword)
                        new_detections.append({
                            "category": category,
                            "keyword": keyword,
                            "label": pattern_info["label"],
                            "description": pattern_info["description"],
                        })

        # 공식 절차 근거 매칭
        for org_keyword, procedures in OFFICIAL_PROCEDURES.items():
            if org_keyword in message:
                for proc in procedures:
                    if proc not in self.procedures:
                        self.procedures.append(proc)
                        new_procedures.append(proc)

        # 위험도 재계산
        self._recalculate_risk()

        # 위험 등급 판정
        risk_level = self._get_risk_level()

        # 결과 반환
        return {
            "message": message,
            "new_detections": new_detections,
            "new_procedures": new_procedures,
            "risk_score": self.risk_score,
            "risk_level": risk_level,
            "total_detected_patterns": dict(self.detected_patterns),
            "total_procedures": list(self.procedures),
        }

    def _recalculate_risk(self):
        """감지된 패턴 기반 위험도 재계산"""
        score = 0
        for category, keywords in self.detected_patterns.items():
            pattern_info = PHISHING_PATTERNS[category]
            base_weight = pattern_info["weight"]
            # 같은 카테고리에서 여러 키워드가 감지될수록 확신도 증가
            keyword_count = len(keywords)
            # 첫 키워드는 base_weight, 추가 키워드마다 5점씩 가산 (최대 base_weight)
            category_score = base_weight + min(keyword_count - 1, 3) * 5
            score += category_score

        # 복합 패턴 보너스 (2개 이상 카테고리 동시 감지)
        num_categories = len(self.detected_patterns)
        if num_categories >= 3:
            score += 15
        elif num_categories >= 2:
            score += 10

        self.risk_score = min(score, 100)

    def _get_risk_level(self) -> dict:
        """위험 등급 반환"""
        if self.risk_score >= 80:
            return {
                "level": "critical",
                "emoji": "🚨",
                "label": "보이스피싱 확정",
                "color": "#FF0000",
                "action": "즉시 통화를 종료하세요!",
            }
        elif self.risk_score >= 50:
            return {
                "level": "high",
                "emoji": "⚠️",
                "label": "보이스피싱 의심",
                "color": "#FF8C00",
                "action": "주의하세요. 개인정보를 절대 알려주지 마세요.",
            }
        elif self.risk_score >= 20:
            return {
                "level": "caution",
                "emoji": "ℹ️",
                "label": "주의 필요",
                "color": "#FFD700",
                "action": "대화 내용에 주의를 기울이세요.",
            }
        else:
            return {
                "level": "safe",
                "emoji": "✅",
                "label": "정상 통화",
                "color": "#28A745",
                "action": "현재까지 위험 패턴이 감지되지 않았습니다.",
            }

    def get_summary(self) -> dict:
        """현재까지의 분석 요약"""
        return {
            "conversation_length": len(self.conversation),
            "risk_score": self.risk_score,
            "risk_level": self._get_risk_level(),
            "detected_categories": list(self.detected_patterns.keys()),
            "detected_keywords": dict(self.detected_patterns),
            "official_procedures": list(self.procedures),
        }

    def reset(self):
        """대화 초기화"""
        self.__init__()


# ============================================================
# 5. 시나리오 프리셋 (데모용)
# ============================================================
DEMO_SCENARIOS = {
    "검찰 사칭형": [
        "안녕하세요, 서울중앙지검 첨단범죄수사부 김수사관입니다.",
        "본인 명의 계좌가 대포통장으로 사용된 정황이 포착되었습니다.",
        "지금 즉시 조치를 취하지 않으면 공범으로 체포 영장이 발부될 수 있습니다.",
        "본인 확인을 위해 주민등록번호와 계좌번호를 말씀해주세요.",
        "자금 보호를 위해 금감원 안전계좌로 전액 이체해주셔야 합니다.",
    ],
    "금감원 사칭형": [
        "금융감독원 소비자보호팀입니다.",
        "고객님 명의로 불법 대출이 실행된 것이 확인되었습니다.",
        "피해 방지를 위해 긴급 조치가 필요합니다. 비밀 유지가 중요합니다.",
        "본인 확인을 위해 계좌번호와 비밀번호를 알려주세요.",
        "안전계좌로 자금을 이체하시면 보호 조치가 완료됩니다.",
    ],
    "경찰 사칭형": [
        "경찰청 사이버수사대입니다.",
        "고객님 개인정보가 범죄에 악용된 것으로 확인됩니다.",
        "수사 협조를 위해 보안 앱을 설치해주셔야 합니다.",
        "원격 제어를 통해 악성코드 검사를 진행하겠습니다.",
        "수사 진행 중이므로 가족에게 알리면 수사에 방해가 됩니다.",
    ],
    "정상 전화 (택배)": [
        "안녕하세요, CJ대한통운입니다.",
        "김모씨 고객님 택배가 도착했는데 부재중이셔서 연락드렸습니다.",
        "오늘 오후 3시에 재배송 가능할까요?",
    ],
}
