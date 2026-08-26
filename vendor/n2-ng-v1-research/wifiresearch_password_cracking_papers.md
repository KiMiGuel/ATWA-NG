# Password Cracking Research Brief: Theory & Application (2019–2026)

Scope: curated, verified papers relevant to a cracking pipeline (OSINT → empirical dicts → rules → PCFG → PRINCE → mask). Assumed already known and **not** re-covered here: the S&P 2023 guessing-curve paper (i.e., Confident Monte Carlo — listed briefly under Foundational Theory for completeness), Lundberg 2019 (PCFG / language-matched dictionaries), and Prob-Hashcat 2024 (RAID). All titles, venues, and links verified against arXiv, USENIX, IEEE DL, ACM DL, NDSS sites, or author pages. Newest first within each section.

---

## 1. Foundational Theory (guessing numbers, entropy, strength estimation)

- **Confident Monte Carlo: Rigorous Analysis of Guessing Curves for Probabilistic Password Models** — Liu, Blocki, Bai. **IEEE S&P 2023**, pp. 626–644. Shows standard Monte Carlo guess-number estimation (Dell'Amico & Filippone CCS'15) can be badly inaccurate for rare passwords; provides high-confidence upper/lower bounds on guessing numbers and the full guessing curve (λ_{M,B}). The "tools 14% vs ideal 39%" finding context lives here.
  - PDF: https://par.nsf.gov/servlets/purl/10505354
- **Can Foundation LLMs Accurately Estimate Password Strength?** — (S&P 2026, Blaser et al.; useful bibliography of strength-estimation work). Evaluates whether foundation LLMs can replace model-based guessing numbers.
  - PDF: https://www.blaseur.com/papers/passllm-sp2026.pdf
- **On the Account Security Risks Posed by Password Strength Meters** — Xu, Han, Yu, Liu, Zhang, Lin, Dong. **AsiaCCS 2025**. Shows deployed meters (zxcvbn-class) are systematically gameable by modern guessing models — attacker-relevant because it quantifies divergence between meter score and true guessability.
  - PDF: https://arxiv.org/abs/2505.08292
- **On the Economics of Offline Password Cracking** — Blocki, Harsha, Zhou. **IEEE S&P 2018** (foundational for pipeline costing: optimal attacker cost model, why memory-hard KDFs matter).
  - PDF: https://arxiv.org/abs/2006.05023
- **zxcvbn: Low-Budget Password Strength Estimation** — Wheeler. **USENIX Security 2016**, pp. 157–173 (reference point for successor meters).
  - https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/wheeler
- **Interpretable Probabilistic Password Strength Meters via Deep Learning** — Pasquini, Ateniese, Bernaschi. **ESORICS 2020**, pp. 502–522 (neural guess-number meters; zxcvbn successor line).
- **Reducing Bias in Modeling Real-world Password Strength via Deep Learning and Dynamic Dictionaries** — Pasquini, Cianfriglia, Ateniese, Bernaschi. **USENIX Security 2021**, pp. 821–838 (training-set distribution bias — critical for choosing training corpora in a pipeline).
- **MAYA: Addressing Inconsistencies in Generative Password Guessing through a Unified Benchmark** — Pasquini et al. **arXiv 2025** (benchmarking methodology; how to fairly compare models across leaks — read before designing your own evaluation).
  - https://arxiv.org/abs/2504.16651

## 2. Guessing Models: PCFG / Markov / PRINCE / Rules

### PCFG advances
- **Using Parallel Techniques to Accelerate PCFG-based Password Cracking Attack** — Xu, Zhang, Zhang, Zhang, Zhang, Yu, Cheng, Han. **IEEE TDSC 2025**. Directly addresses PCFG's main pipeline weakness (slow, CPU-bound probability-ordered generation).
- **SE#PCFG: Semantically Enhanced PCFG for Password Analysis and Cracking** — Wang et al. **arXiv 2306.06824 (v2 2025; IEEE TDSC version)**. 43 semantic categories across EN/ZH/DE/FR leaks; SEPCA cracker beats PCFG variants and NN baselines by up to ~21% (user-level). The semantic-PCFG line the user asked about.
  - https://arxiv.org/abs/2306.06824
- **LPG–PCFG: Improved Probabilistic Context-Free Grammar for Passwords** — **Security & Communication Networks / PMC 2022** (word-extraction improvements to PCFG tokenization).
  - https://pmc.ncbi.nlm.nih.gov/articles/PMC9227161/
- **TransPCFG: Transferring the Grammars from Short Passwords to Guess Long Passwords Effectively** — Han, Xu, Zhang, Wang, Zhang, Wang. **IEEE TIFS 2021**, 16:451–465. Key for passphrase/long-password stages of the pipeline.
- **Chunk-Level Password Guessing** — Xu, Wang, Yu, Zhang, Zhang, Han. **ACM CCS 2021**, pp. 5–20. Refines PCFG terminal modeling at chunk level. DOI: 10.1145/3460120.3484743.
- **On Practical Aspects of PCFG Password Cracking** — Hranický, Lištiak, Mikuš, Ryšavý. **IFIP DBSec 2019**, pp. 43–60. Operational PCFG tuning (smoothing, capitalization, keyboard walks, Markov backfill). DOI: 10.1007/978-3-030-22479-0_3. PDF: https://inria.hal.science/hal-02384606/document
- **Improved PCFGs for Passwords Using Word Extraction** — Cheng et al., **IEEE ICASSP 2021**, pp. 2690–2694.

### Markov / ordered enumeration
- **OMEN: Faster Password Guessing Using an Ordered Markov Enumerator** — Dürmuth et al. **ESSoS 2015** (the model Prob-Hashcat accelerates; baseline for Markov-ordered generation).
- **Dynamic Markov Model: Password Guessing Using Probability Adjustment** — Guo et al. **Applied Sciences 2021**, 11:4607. DOI: 10.3390/app11104607.
- **WordMarkov: A Password Probability Model of Semantics** — Xie et al. **IEEE ICASSP 2022**, pp. 3034–3038.

### PRINCE / rule engine
- PRINCE has essentially no peer-reviewed literature: the canonical reference is the hashcat documentation and the princeprocessor tool (Jens "atom" Steube). Academic treatment appears only inside tool comparisons (PassGAN, PassBERT, PCFG papers above). Closest adjacent work:
- **Digit Semantics Based Optimization for Practical Password Cracking Tools** — Zhang, Wang, Ruan, Zhang, Xu, Han. **ACSAC 2021**, pp. 513–527. Optimizes digit handling in hashcat/JtR-style mangling. DOI: 10.1145/3485832.3488025.
- **PassBERT (bi-directional transformers), adaptive rule-based guessing mode** — Xu et al. **USENIX Security 2023**, pp. 1001–1018. Learns which mangling rule to apply per base word — a learned rule engine; outperforms static rulesets by 4.86%.
  - https://www.usenix.org/conference/usenixsecurity23/presentation/xu-ming
- **Reasoning Analytically about Password-Cracking Software** — Liu, Nakanishi, Golla, Cash, Ur. **IEEE S&P 2019**, pp. 380–397. Reverse-engineers JtR/hashcat rule behavior analytically — the foundational "rule engine research" paper.

## 3. ML-Based Cracking

- **MoPE: A Mixture of Password Experts for Improving Password Guessing** — Duan, Xu, Zhang, Han. **IEEE S&P 2026**. Mixture-of-experts password model; SOTA as of writing.
  - https://arxiv.org/abs/2509.16558
- **Password Guessing Using Large Language Models (PASSLLM)** — Zou, An, Wang. **USENIX Security 2025**, pp. 7799–7818. LoRA fine-tuned decoder-only LLMs; four scenarios (trawling, PII-targeted, reuse-targeted, PII+reuse); +2.9–17% over prior SOTA; 11.5× distillation speedup. Unofficial code: https://github.com/Tzohar/PassLLM
- **RankGuess: Password Guessing Using Adversarial Ranking** — Yang, Wang. **IEEE S&P 2025**, pp. 682–700. RL/adversarial-ranking framing (MDP) covering trawling, mask-style, and PII guessing. PDF: https://wangdingg.weebly.com/uploads/2/0/3/6/20366987/ieeesp25-guessing-full.pdf
- **KAPG: Adaptive Password Guessing via Knowledge-Augmented Generation** — **arXiv 2510.23036 (2025)**. Retrieval-augmented password guessing.
- **KAPG-adjacent: LLM-Guided Prompt Evolution for Password Guessing** — **arXiv 2604.12601 (2026)**. Prompt-evolution attacks using general LLMs.
  - https://arxiv.org/abs/2604.12601
- **Universal Neural-Cracking-Machines: Self-Configurable Password Models from Auxiliary Data (UNCM)** — Pasquini, Ateniese, Troncoso. **IEEE S&P 2024**, pp. 1365–1384. Self-configuring model conditioned on auxiliary data (e.g., emails) — estimates group password strength without plaintext access.
- **PassBERT: Improving Real-world Password Guessing Attacks via Bi-directional Transformers** — Xu et al. **USENIX Security 2023**, pp. 1001–1018 (see §2; pre-train/fine-tune paradigm for conditional, targeted, and rule-adaptive guessing).
- **PassGPT: Password Modeling and (Guided) Generation with Large Language Models** — Rando, Perez-Cruz, Hitaj. **ESORICS 2023**, pp. 164–183. GPT-2-class model, +20% over prior deep generative models; guided generation under constraints; PassVQT variant. arXiv: https://arxiv.org/abs/2306.01545
- **PagPassGPT: Pattern Guided Password Guessing via Generative Pretrained Transformer** — Su et al. **arXiv 2404.04886 (2024)**. Structure-pattern-guided GPT generation (PCFG-meets-GPT).
- **PassTSL: Modeling Human-Created Passwords through Two-Stage Learning** — Wang et al. **ACISP 2024**, arXiv 2407.14145.
- **Password Guessing Using Random Forest** — Wang, Zou, Zhang, Xiu. **USENIX Security 2023**, pp. 965–982. Non-neural ML baseline that beats several DL models — worth a slot in the pipeline ensemble.
- **PassFlow: Guessing Passwords with Generative Flows** — Pagnotta, Hitaj, De Gaspari, Mancini. **IEEE DSN 2022**, pp. 251–262 (normalizing flows give exact probability ordering, unlike GANs).
- **GNPassGAN: Improved GANs for Trawling Offline Password Guessing** — Yu, Vargas Martin. **IEEE EuroS&PW 2022**, pp. 10–18 (gradient-normalized PassGAN).
- **VAEPass: A Lightweight Password Guessing Model Based on Variational Auto-Encoder** — Yang et al. **Computers & Security 2022**, 114:102587.
- **Improving Password Guessing via Representation Learning** — Pasquini, Gangwal, Ateniese, Bernaschi, Conti. **IEEE S&P 2021**, pp. 1382–1399. Conditional/dynamic password guessing (CPG/DPG), fixes PassGAN mode collapse.
- **PassGAN: A Deep Learning Approach for Password Guessing** — Hitaj, Gasti, Ateniese, Perez-Cruz. **ACNS 2019**, pp. 217–237 (baseline). arXiv: https://arxiv.org/abs/1709.00440; code: https://github.com/brannondorsey/PassGAN
- **GENPass: PCFG rules + adversarial generation** — Liu et al. **IEEE ICC 2018** (precursor, cited for completeness).
- **PGTCN: temporal convolution network guessing model** — Wu et al. **JNCA 2023**, 213:103592.
- **Improving Deep Learning Based Password Guessing Models Using Pre-processing** — Wu, Wang, Zou, Huang. **ICICS 2022** (training-set cleaning gains).

## 4. Targeted / OSINT-Informed Attacks & Password Reuse

- **KNNGuess: Targeted Password Guessing Using k-Nearest Neighbors** — Li, Wang. **NDSS 2026**. Retrieval-augmented targeted model; 25.4% of sister passwords within 100 guesses (common users); beats Pass2Edit/PointerGuess by avg. 18%.
  - https://www.ndss-symposium.org/ndss-paper/targeted-password-guessing-using-k-nearest-neighbors/
- **Improving Targeted Password Guessing by Using PII and Old Password** — **Cybersecurity (Springer) 2025**. Combines TarGuess-style PII with reuse.
  - https://link.springer.com/article/10.1186/s42400-025-00430-0
- **PointerGuess: Targeted Password Guessing Model Using Pointer Mechanism** — Xiu, Wang. **USENIX Security 2024**, pp. 5555–5572. Pointer-network reuse guessing (replaces PG-Pass line).
- **Pass2Edit: A Multi-Step Generative Model for Guessing Edited Passwords** — Wang, Zou, Xiao, Ma, Chen. **USENIX Security 2023**, pp. 983–1000. The credential-tweaking model (24.2%/11.7% at 100 guesses) that KNNGuess/PassLLM-II benchmark against.
- **Araña: Discovering and Characterizing Password Guessing Attacks in Practice** — Islam, Bohuk, Chung, Ristenpart, Chatterjee. **USENIX Security 2023**. Empirical characterization of real guessing attacks against a production service — informs attacker model realism.
- **A Two-Decade Retrospective Analysis of a University's Vulnerability to Attacks Exploiting Reused Passwords** — Nisenoff et al. **USENIX Security 2023**. Breach-corpora → 32% of matched accounts guessable; verbatim-breach passwords 4× more exploited than tweaked guesses. Direct pipeline validation for the OSINT→empirical stages.
  - https://www.usenix.org/conference/usenixsecurity23/presentation/nisenoff-retrospective
- **Beyond Credential Stuffing: Password Similarity Models Using Neural Networks** — Pal, Daniel, Chatterjee, Ristenpart. **IEEE S&P 2019**, pp. 417–434. Seq2seq sister-password prediction (Pass2RNN/Pass2Path); foundational reuse-attack paper.
- **Passtrans: Improved Password Reuse Model Based on Transformer** — He et al. **IEEE ICASSP 2022**, pp. 3044–3048.
- **PG-Pass: Targeted Online Guessing via Pointer Generator Networks** — Li et al. **IEEE CSCWD 2022**, pp. 507–512 (PII-targeted).
- **Targeted Online Password Guessing: An Underestimated Threat (TarGuess I–IV)** — Wang, Zhang, Wang, Yan, Huang. **ACM CCS 2016**, pp. 1242–1254 (baseline PII taxonomy still used by all targeted papers above).
- **Birthday, Name and Bifacial-Security: Understanding Passwords of Chinese Web Users** — Wang, Wang, He, Tian. **USENIX Security 2019**, pp. 1537–1555 (cross-lingual PII patterns; complements Lundberg).
- **Using Personal Information in Targeted Grammar-based Probabilistic Password Attacks** — Houshmand, Aggarwal. **Advances in Digital Forensics 2017** (TarPCFG — PCFG stage + OSINT).

## 5. Passphrase Research

- **Password and Passphrase Guessing with Recurrent Neural Networks** — Nosenko, Cheng, Chen. **Information Systems Frontiers 2022**. LSTM/GPT-2 passphrase prediction; up to 40% full-passphrase recovery from the initial word; Markov baseline comparison. DOI: 10.1007/s10796-022-10325-x.
- **TransPCFG (TIFS 2021, §2)** — the main PCFG-for-long-passwords/passphrase work.
- Brainwallet/passphrase-entropy evidence (empirical): Vasek et al. brainwallet study and Kuo et al. mnemonic passphrases (SOUPS 2006), re-summarized in **GeoVault** (MDPI Mathematics 2026) §2 — confirms human passphrases suffer large entropy collapse under statistical guessing. https://www.mdpi.com/2227-7390/14/10/1653
- Background: Bonneau & Shutova, *Linguistic properties of multi-word passphrases* (FC 2012) — the n-gram/POS structure most passphrase crackers exploit.

## 6. Tools & Implementations

| Tool / Code | What | URL |
|---|---|---|
| pcfg_cracker (Matt Weir/lakiw) | PCFG trainer + guesser, v4.x line (Trainer 4.4, Guesser 4.6, PRINCE_LING 4.3); supports Markov bruteforce backfill, keyboard walks, OMEN-style ordering | https://github.com/lakiw/pcfg_cracker |
| PassGAN | IWGAN generator; RockYou pretrained model | https://github.com/brannondorsey/PassGAN |
| PassLLM (unofficial) | PyTorch reimplementation of USENIX Sec'25 PassLLM (PII + LoRA) | https://github.com/Tzohar/PassLLM |
| hashcat | Rules, PRINCE (-a 8 / princeprocessor), mask, Markov (hcstat2) | https://hashcat.net/hashcat/ |
| John the Ripper | Markov mode, rules, --stdin feeding from PCFG/OMEN generators | https://www.openwall.com/john/ |
| princeprocessor / pp64 | Standalone PRINCE candidate generator | https://github.com/hashcat/princeprocessor |
| OMEN | Ordered Markov enumerator | https://github.com/RUB-SysSec/OMEN |
| CUPP | OSINT/PII wordlist profiler (feeds targeted stage) | https://github.com/Mebus/cupp |
| zxcvbn | Reference strength estimator (meters section) | https://github.com/dropbox/zxcvbn |
| Prob-Hashcat | GPU-accelerated probabilistic guessing (RAID 2024; already known) | PDF: https://wangdingg.weebly.com/uploads/2/0/3/6/20366987/raid24-n1-v7.pdf |

## 7. Credential-Stuffing Defenses that Define the Attacker Model

- **Protecting Accounts from Credential Stuffing with Password Breach Alerting** — Thomas et al. (Google). **USENIX Security 2019**. Private-set breach alerting at scale; defines what leaks defenders see vs. attackers.
- **Protocols for Checking Compromised Credentials (C3)** — Li, Pal, Ali, Sullivan, Chatterjee, Ristenpart. **ACM CCS 2019**, pp. 1387–1403; k-anonymity/private C3 protocols.
- **Might I Get Pwned: Second Generation Compromised Credential Checking** — Pal et al. **USENIX Security 2022**. MIGP; identifies password-similarity attacks as the uncovered threat → motivates Pass2Edit/KNNGuess-style tweaking in your pipeline's reuse stage.
- **How to End Password Reuse on the Web** — Wang & Reiter. **NDSS 2019**; plus **Detecting Stuffing of a User's Credentials at Her Own Accounts** — Wang & Reiter. **USENIX Security 2020** (cross-site stuffing detection → tells you lockout/throttling budgets for online stages). PDF: https://www.usenix.org/system/files/sec20-wang.pdf
- **How to Attack and Generate Honeywords** — Wang, Zou, Dong, Song, Huang. **IEEE S&P 2022**, pp. 966–983. Targeted honeyword attackers (TarGuess-based); quantifies how PII breaks decoy defenses — doubles as an OSINT-attack evaluation framework.

## 8. Open Problems & Gaps

1. **PRINCE/combinator attacks lack formal analysis.** No peer-reviewed probability model of PRINCE ordering exists; pipeline placement of PRINCE vs. PCFG-LING is currently folklore. Opportunity: model PRINCE keyspace as a distribution over word-concatenation lengths and merge with PCFG pre-terminals.
2. **Ensemble ordering across models.** MAYA (2025) shows results are inconsistent across leaks; nobody has a principled method for interleaving guesses from heterogeneous models (PCFG ∩ Markov ∩ LLM) in probability order. RankGuess (S&P 2025) is the closest step.
3. **Mask/hybrid attacks are academically orphaned.** Almost no theory on optimal mask selection or dictionary×mask hybrid ordering; PassBERT's adaptive-rule mode and Prob-Hashcat's base/modifier split are the only serious attempts.
4. **LLM guessing cost/benefit unresolved.** PassLLM (USENIX'25) wins at ≤10³ guesses but distillation is needed for scale; whether LLMs beat PCFG at 10¹¹+ trawling budgets is untested (S&P'25 RankGuess authors argue LLM token vocabularies are fundamentally mismatched to passwords).
5. **Multilingual/cross-site transfer.** SE#PCFG (2023/25) and Lundberg show language matching matters, but transfer between scripts (e.g., pinyin-in-ASCII) and between password policies is weakly studied beyond TransPCFG.
6. **Guessing-curve confidence at pipeline scale.** Confident Monte Carlo (S&P'23) bounds single-model curves; no work bounds the union/ensemble curve an actual multi-tool pipeline produces — this is exactly the 14% vs 39% gap.
7. **Passphrase defenses lag attacks.** RNN/GPT-2 passphrase guessing (ISF 2022) beats Markov 2×, but no modern PCFG/LLM passphrase cracker or benchmark exists; Diceware-style random-word passphrases vs. natural-language passphrases are rarely separated in evaluations.
8. **Defense-aware online guessing.** Araña (USENIX'23) and Wang–Reiter (USENIX'20) characterize throttling/detection, but targeted models (TarGuess, PassLLM-I/III) still assume static lockout budgets — adaptive attackers vs. risk-based authentication (NDSS'25 RBA work) is open.
