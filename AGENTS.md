# AGENTS.md

## Project

This is a Russian diploma project for Bauman Moscow State Technical University.

Topic:
«Разработка средства автоматизации процессов анализа и оценки рисков информационной безопасности корпоративных систем банка на основе машинного обучения».

The project includes:
- FastAPI backend;
- risk/event processing pipeline;
- ML classifier;
- SQLite storage;
- optimization of control measures;
- web UI;
- thesis text in Russian.

## Main goal

The project must implement a practical prototype for automated analysis and assessment of information security risks in corporate banking systems.

The target processing chain is:

raw logs / SIEM records
→ information security events
→ information security incidents
→ risk events related to implementation of information threats
→ risk assessment
→ graph adjustment
→ control measure optimization
→ SQLite storage
→ API/UI.

The main new package should be:

risk_system/event_pipeline

Expected entity chain:

RawLogRecord
→ NormalizedSecurityEvent
→ IncidentRecord
→ RiskEventRecord
→ RiskAssessmentRecord
→ ControlOptimizationResult.

## Classifiers

Classifier 1:
information security events → information security incidents.

Implementation:
formalized expert rules + event correlation.

Do not turn the first classifier into the main ML model.

Classifier 2:
information security incidents → risk events related to implementation of information threats.

Implementation:
ML model.

It estimates:

P(y = 1 | X)

where y = 1 means that the incident is classified as a risk event related to implementation of information threats.

## Mathematical model

Preserve the old mathematical optimization core:
- protected objects;
- threat implementation scenarios;
- control measures;
- initial risk;
- residual risk;
- control effectiveness;
- binary control-selection variables;
- budget constraints;
- labor constraints;
- branch-and-bound method.

Do not inflate Chapter 2 with many new sets for logs/events/incidents. The chain:

logs → information security events → information security incidents → risk events

should mainly explain how p_ij^* is formed.

Use:

r_ij^0 = p_ij^* · I_ij

Do not use:

risk = probability × impact × criticality

Asset significance must be included in I_ij, not used as a separate multiplier.

Do not include implementation time T as a mathematical constraint.

Allowed constraints:
- budget;
- labor;
- optionally maximum number of selected controls K.

R(x) is only an internal objective function for control selection. Do not describe it as a normative total risk indicator of the bank.

## Risk optimization

The residual risk model should be:

r_ij(x) = max(0, r_ij^0 - sum_h a_ijh x_h)

where:
- r_ij^0 is the initial calculated risk estimate;
- a_ijh is the expected effect of control h for the pair “protected object — threat implementation scenario”;
- x_h is a binary variable indicating whether control h is selected.

The optimization objective:

R(x) = sum_i sum_j r_ij(x) → min

The equivalent transformation to maximization of control effect may be used:

sum_h A_h x_h → max

where:

A_h = sum_i sum_j a_ijh.

## Bayesian module

The Bayesian module is planned as an additional probability adjustment component.

Expected placement:

RiskEventMLClassifier
→ BayesianRiskEventAdjuster
→ RiskEventAssessmentEngine

The Bayesian module should:
- adjust p_ij^* based on dependencies between threat implementation scenarios;
- not replace the ML classifier;
- not calculate risk by itself;
- not replace I_ij;
- store explanation/evidence for any probability adjustment.

Examples of dependencies:
- account compromise → unauthorized access;
- unauthorized access → privilege escalation;
- privilege escalation → data leak;
- misconfiguration → malware activity.

## Graph adjustment

Graph adjustment is used after local risk assessment.

Use wording:
“graph adjustment of the calculated risk estimate”.

Avoid wording:
“mechanical risk propagation through the whole infrastructure”.

Graph adjustment should:
- use infrastructure links between protected objects;
- adjust priority or final calculated estimate;
- not replace the local risk estimate;
- avoid uncontrolled risk growth.

## Legal and regulatory wording

Use Russian regulatory terminology carefully.

ГОСТ Р 57580.1-2017:
connect with information security events and information security incidents.

ГОСТ Р 57580.3-2022:
connect with risk events related to implementation of information threats.

Положение Банка России № 716-П:
connect with event database, banking context, operational risk, and information security risk.

152-ФЗ:
include in the legal chapter carefully as a personal data constraint when real personal data is processed.

Also use:
- Конституция РФ;
- Доктрина информационной безопасности РФ;
- 149-ФЗ;
- 395-1;
- ГОСТ Р 57580.1-2017;
- ГОСТ Р 57580.3-2022;
- ГОСТ Р 59898-2021 and/or related AI/ML standards if relevant.

## Terms to avoid

Do not use:
- риск-балл;
- опасное состояние;
- истинная вероятность угрозы;
- совокупный риск банка as a normative indicator;
- probability × impact × criticality;
- criticality as a separate multiplier in the risk formula.

Use instead:
- расчётная оценка риска;
- исходная расчётная оценка риска;
- остаточная расчётная оценка риска;
- событие риска реализации информационной угрозы;
- вероятностная составляющая;
- оценка последствий;
- класс риска;
- приоритет обработки.

## Code style

Use Python 3.12 compatible code.

Use:
- FastAPI;
- Pydantic;
- scikit-learn;
- pandas;
- SQLite;
- joblib;
- HTML/CSS/JS for the simple UI.

Do not break existing endpoints unless explicitly asked.

Prefer:
- adding /pipeline/full as the main workflow endpoint;
- keeping old /assess, /train, /optimize backward compatible or clearly marking them as legacy.

## UI

The UI should be adaptive and demonstrate the full workflow:

logs
→ events
→ incidents
→ risk events
→ risk assessments
→ controls.

The UI should include:
- JSON upload;
- /pipeline/full execution;
- risk assessment tables;
- incident and risk event tables;
- control recommendations;
- SQLite summary;
- ML training via CSV/JSON;
- responsive layout for smaller screens.

## Thesis text style

Write thesis text in Russian.

Use strict academic style suitable for Bauman MSTU.

Avoid:
- template-like paragraphs;
- generic filler;
- cliché endings like “Таким образом”;
- excessive bullet lists in final thesis chapters.

Use English only for established technical terms and abbreviations:
ML, API, SIEM, EDR, SQLite, FastAPI.

Do not mention internal chat history or “as discussed earlier”.

## Chapter 2 structure

Use this structure:

2.1 Постановка задачи оценки и обработки рисков ИБ  
2.2 Формирование исходной оценки риска  
2.3 Модель выявления инцидентов защиты информации  
2.4 ML-модель отнесения инцидентов к событиям риска реализации информационных угроз  
2.5 Оценка последствий реализации сценария информационной угрозы  
2.6 Байесовское уточнение вероятностной оценки  
2.7 Графовое уточнение расчётной оценки риска  
2.8 Модель остаточного риска после выбора мер защиты  
2.9 Оптимизационная постановка выбора мер защиты  
2.10 Преобразование задачи к максимизации эффекта мер защиты  
2.11 Метод решения задачи выбора мер защиты  
2.12 Итоговая математическая модель  
2.13 Связь математической модели с архитектурой программного средства  

Important:
Preserve the old mathematical optimization core. Do not turn Chapter 2 into a huge formalization of logs/events/incidents. The log/event/incident/risk-event chain should mainly explain how p_ij^* is formed.