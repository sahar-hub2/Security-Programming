<!-- @format -->

# Reflective Commentary - Secure Overlay Chat Protocol (SOCP)

Developed by Group 12 for the University of Adelaide Security Programming course, 2025

## Introduction: Context and Purpose

This report reflects on Group 12’s experience developing the Secure Overlay Chat Protocol (SOCP v1.3) for the Advanced Secure Programming assignment. It focuses on the design and implementation of a secure, standards-compliant version, alongside a deliberately backdoored version for controlled peer review. The commentary critically examines protocol decisions, cryptographic integrity, key management, testing, interoperability, and lessons learned from feedback, while addressing ethical considerations, assumptions, and challenges encountered during the creation and evaluation of vulnerabilities.

## Reflection on the Standardised Protocol

The Secure Overlay Chat Protocol (SOCP) represents a robust, end-to-end encrypted communication framework designed for decentralized networks. Its n-to-n server mesh topology ensures that each server maintains knowledge of its local users while relying on a network-wide directory for routing messages securely between servers. Every payload is encrypted using RSA-4096 with OAEP for encryption and PSS for signatures, guaranteeing confidentiality and integrity without relying on symmetric key distribution.
SOCP leverages WebSocket (RFC 6455) as the mandatory transport layer, providing real-time, bidirectional communication for both server-to-server and user-to-server messaging. Initially, our group considered TCP due to its straightforward, low-level connections and minimal overhead, reflected in early votes. However, during implementation we realized TCP alone would complicate browser compatibility, asynchronous messaging, and reliable propagation of public channel broadcasts. The voting ultimately favoured WebSocket, recognizing that standardizing on them simplifies client implementation, ensures interoperability, and better supports RSA-4096 encrypted payloads, content signatures, and fan-out of public channel messages. This highlights the tension between low-level control and practical deployment, showing how browser support, persistent connections, and secure broadcast channels decisively shape protocol adoption.
Implementing SOCP gives teams hands-on experience with distributed network coordination, end-to-end encryption, and secure message routing, highlighting the challenges of building a scalable, interoperable chat system. Its design enforces strong security RSA-4096 encryption, signed messages, and transport-level verification, while WebSocket enable persistent, browser-compatible bidirectional messaging, and gossip-based presence updates support fault-tolerant delivery.
Trade-offs include higher computational overhead from RSA-only encryption, limited flexibility due to the mandatory public channel, and added complexity in managing per-user keys and broadcast fan-out. Multi-server routing and gossip updates may also introduce latency in larger networks. Overall, SOCP provides a rigorous, security-first framework that balances standardization, reliability, and real-world implementation challenges.

## Backdoor Design and Exploitation

-   1. Weak-key acceptance
       A conditional flag in the backdoored keys.py/key registration flow permits registration of RSA keys significantly weaker than the mandated RSA-4096. The backdoored PoC demonstrates registering a 1024-bit key and having the system accept it as if it were a 4096-bit key.
       Rationale: Purpose is to show how cryptographic strength is only as good as key management and verification. It is often assumed "if the algorithm is strong (RSA-OAEP/PSS) then the system is secure." Accepting weak keys demonstrates that logical or policy-level mistakes entirely undermine cryptography.
       How it’s subtle and plausible: The backdoor is subtle because all runtime messaging still uses RSA-OAEP and RSASSA-PSS APIs. Inspecting traffic looks encrypted, signed; only the key length verification step is lax. A reviewer who checks only "RSA is used" without verifying key sizes or certificate policies will miss the weakness. The system's outward behavior remains functional; no immediate errors, which makes the flaw plausible in real-world deployments where legacy devices produce weak keys.
       Impact: Accepted weak keys allow offline cryptanalysis or key-forgery attacks, leading to impersonation, decryption, or signature forgery against participants that assume key strength.
       Evidence: poc_weak_key_register.py demonstrates registering a weak key and having the system accept it. Use this PoC to reproduce the behavior in a controlled lab.
-   2. Unsigned gossip acceptance
       The backdoored server.py contains a debug-mode conditional that, when enabled, allows acceptance and relay of USER_ADVERTISE and other introducer gossip frames without successful signature verification. This effectively disables the canonical signature check for federated advertisements and allows arbitrary adverts to be injected into the network.
       Rationale: Purpose is to demonstrate how a small logic change (bypassing one verification condition) can defeat an otherwise robust signature-based security model. The aim is to help reviewers see how trust assumptions in the gossip flow are fragile when signature verification is not enforced end-to-end.
       How it’s subtle and plausible: The gossip pipeline still uses the same JSON envelope format and signature fields; only the signature verification gate is bypassed under an internal flag. Reviewers may see normal envelope shapes and assume signature checks are present if they don't inspect the verification branch. Because messages continue to flow correctly, the issue is easily overlooked during functional testing.
       Impact: An injected unsigned advert can be propagated across servers, enabling attacker-controlled identities to be trusted and used for impersonation or message routing attacks.
       Evidence: poc_inject_unsigned_advert.py demonstrates how a crafted unsigned advert can be injected and propagated when the backdoor flag is active
       Detection and Mitigation
       • (Weak-key acceptance) Enforce cryptographic policy centrally (reject keys < RSA-3072 at import/generation; fail CI on violation). Mitigation can be done by removing runtime flags that short-circuit verification; make any debug bypass compile-time and blocked from production.
       • (Unsigned gossip acceptance) Centralize signature verification into an auditable function and add unit/property tests that assert every relayed advert passed verification. By adding CI regression tests (unsigned/invalid adverts, sub-policy keys) and log verification anomalies, this issue can be mitigated.
       Ethical considerations and safeguards applied
       The backdoors are intentionally confined to a clearly labelled backdoored_version/ and documented in BACKDOOR_README.md with explicit instructions to run only in isolated lab environments. Documented the PoCs and quarantine instructions to avoid accidental deployment.

-   Describe what vulnerability your team intentionally introduced
-   Explain your rationale — to illustrate how minor logic flaws (e.g., misplaced validation) can subvert strong cryptography.
-   Reflect on how hard it was to detect: What made it plausible and subtle?
-   Show the exploit conceptually (in appendix).
-   Discuss ethics: how intentional vulnerabilities reveal the fragility of developer assumptions.

## Evaluation of Received Feedback

-   Backdoors: Check if other groups detected any intentionally left debug or test backdoors.
-   Code Issues: Note if they identified security flaws, input validation problems, or logic errors.
-   Usefulness: Assess whether the feedback was clear, actionable, and helped improve your project.
-   Overall Reflection: Summarize key insights and any gaps in their review.

## Feedback Provided to Other Groups

The following feedback was provided by Sahar Hassan Alzahrani to groups 29, 100, and 42 on their secure chat system projects.
Feedback for Group 29’s chat system highlighted strengths in design and modern library usage, while identifying vulnerabilities such as hardcoded keys, insecure cookies, unsafe logging, and unencrypted WebSocket.
A key challenge in this review was that I had not previously worked with some of these modern libraries, and the project included multiple components, including a frontend,
which required additional effort to understand and correctly apply static and dynamic analysis tools.
For Group 100’s Secure Overlay Chat System, the review emphasized robust thread-safe design, structured message headers, and session-specific keys, yet critical issues were identified,
including unauthenticated debug backdoors, weak MD5-derived IVs, binding to all network interfaces, broad exception handling, and input-validation deficiencies.
A primary challenge in this case was interpreting complex runtime behaviours and reproducing crashes safely, which I addressed through focused fuzzing harnesses, manual code tracing,
and embedding reproducible examples. Transitioning to Group 42, their Rust-based Secure Chat Protocol demonstrated strong type safety, structured identifier abstractions,
and resilient error handling under fuzzed input. Static and dynamic analyses revealed timing side-channels in RSA signing, insecure WebSocket usage, unvalidated FromStr parsing, and weak key management,
underscoring the importance of rigorous input validation, secure transport channels, and robust cryptographic hygiene. The challenge in reviewing this group was navigating Rust-specific idioms and cryptographic abstractions while maintaining clarity in recommendations.
The full, detailed reviews and supporting evidence are provided in the Appendix.

-- Abidul Kabir --
During the implementation of the secure chat system, the following were some of the feedbacks given to group 69, group 41 and group 25 by Abidul Kabir.

Group 69 introduced a modular system that was well structured with working encryption and message handling. Nevertheless, the hardcoded or weak RSA parameters, the absence of TLS support, and the absence of authentication handshakes along with the risk of unsafe SQL query construction were found using both the static analysis (Bandit) and the manual one. The excessive exception silencing and absence of documentation was also identified by the code quality checks.
The Group 41 also offered a test mode, which posed severe threats of 1024-bit RSA keys, disabled replay protection and allowing identity registration. Although Bandit was able to detect only minor problems, these backdoors were identified during the manual review. The ability to distinguish between deliberate flaws and actual design weaknesses was another major problem, which was resolved by using ethical testing and config inspection.
Group 25 possessed a secure functional set up. Some of the key weaknesses were absence of TLS, poor key enforcement, and insecure validation with assert statements. The system failed to authenticate identities correctly and lacked important security functions such as message validation and formatted error processing. An inspection was performed both manually and using the static tools and showed several input validation and transport-layer vulnerabilities.
The main obstacle that was evident in all reviews was the correlation of the findings of tools with real-life attack situations. This was checked with combined Bandit, Pylint, manual tracing and runtime experiments. The full reviews and evidence is presented in the Appendix.

Peer Review Summary Debasish Saha Pranta.

Debasish Saha Pranta (a1963099) the following were feedbacks as given to Groups 38, 45, and 77 regarding their Secure Chat System projects.

The Group 38 feedback on Secure Chat Architecture received positive mentions on the strong modular design and layered security concepts. The system combined an Introducer, peer servers and the clients who are in communication with each other via encrypted WebSocket messages. The strengths were good documentation, architectural separation that was professionally realized, and the use of RSA-based authentication. Nevertheless, construction problems like lack of some methods generated by Lombok did not allow full execution and dynamic testing. Weak input validation, absence of authentication on WebSocket endpoints, disclosing keys and identifiers in logs, and inadequate error handling were some of the vulnerabilities that were detected during the process of performing static inspection. The key problem in this review was to diagnose errors in the compilation and test functionality without executing the complete system, which meant that it necessitated further manual examination and reasoning of the intended security flows.

In the case of Group 45, Secure Overlay Chat Prototype (SOCP), the review highlighted a well-written and readable Python-based implementation whose architecture is defined as a multi-server (master-local-client) architecture. The presence of good logging, modular design and understanding of the handling of public/ private keys were viewed as strengths. However, instability during the runtime, unfinished message processing and such essential weaknesses as the absence of validation of peer connections, plaintext-only message transfer, rate limiting and excessive logging of sensitive information have been observed. Dynamic testing revealed problems with the disconnection of clients and maintenance of user state. The key difficulty in this case was the consistency of reproducing these runtime crashes, long distance communication between servers, which was alleviated in the process of repetitive testing and debugging.

Lastly, the Secure Chat System by Group 77 showed good mastery of the cryptography and modular architecture. RSA-OAEP encryption and PSS signatures were well used in the project, which is an indication of good cryptographic hygiene. Such positive factors as replay protection, efficient file transfer using chunks, and structured logs that helped to analyze the logs were mentioned. Nonetheless, some weaknesses were identified such as unauthenticated introducer broadcasts, poor inter-server authentication, sensitive logging and absence of rate-limiting when it comes to file transfers. It was tested that there was a risk of denial-of-service and spoofing on federation channels. The main dilemma was to confirm these risks on federated components and how to comprehend a message propagation over a sequence of trust layers, which was tackled by a thorough static analysis and simulation of the runtime scenario.

In all reviews, Debasish showed that he used static inspection, limited runtime analysis, and manual reasoning to evaluate security, correctness and architectural soundness. The aggregate knowledge supported the paramount role of input validation, secure key management, authenticated communication, and resilience testing of constructing secure distributed chat systems.

-   Identify: State your name and the group reviewed.
-   Overview: Brief summary of project purpose and focus areas.
-   Strengths: Highlight well-implemented design or security features.
-   Weaknesses: Identify vulnerabilities or issues; mention tools used (static/dynamic/manual).
-   Challenges: Note any difficulties you faced and how you addressed them.

# Reflection on AI Use

Critically evaluate your use of AI (e.g., ChatGPT) for documentation, debugging, and explanation:

-   Strengths: code organization, error interpretation, concept clarification.
-   Limitations: lack of context for dynamic runtime issues, occasional hallucinations about function names or parameters.
-   Reflect ethically: how AI accelerated understanding but required human verification for cryptographic correctness.
-   End with insight: AI is a valuable teaching assistant, not an oracle — it reinforces critical reading of generated code.

# Reflection on testing

We conducted unit tests to verify the correctness of core functions and integration tests to ensure proper client-server messaging and system behavior.
Security testing .........
Interoperability testing.........
These tests helped identify minor issues, which were resolved to maintain compatibility and functional integrity. Detailed test scripts, results, and documentation are provided in the GitHub repository and Appendix,
giving a clear record of our testing methodology and outcomes.

# Group Contributions

-   Debasish Saha Pranta: introducer YAML, server-server, backdoor implementation …
-   Samin Yeasar Seaum: file transfer, cryptographic, backdoor implementation … …
-   Abidul Kabir: server-client protocol flow, socket handling, database persistence…
-   Sahar Alzahrani: Built the initial client-server framework with WebSocket messaging and RSA security; added documentation, testing, secure-version validation, and organized the project.
-   Mahrin Mahia: backdoor design and testing…
-   Maria Hasan Logno: test case integration, interoperability experiments…

# Conclusion

-   Summarize the overall growth: from implementing a secure system to realizing how human error undermines security.
-   Emphasize learning outcomes: protocol discipline, ethical coding, cryptographic transparency.
-   Connect to the cybersecurity skill shortage: real-world demand for developers who understand both the defensive and offensive sides of secure software.

# Group 12:

1.  Debasish Saha Pranta (a1963099, debasishsaha.pranta@student.adelaide.edu.au)
2.  Samin Yeasar Seaum (a1976022, saminyeasar.seaum@student.adelaide.edu.au)
3.  Abidul Kabir (a1974976, abidul.kabir@student.adelaide.edu.au)
4.  Sahar Alzahrani (a1938372, sahar.alzahrani@student.adelaide.edu.au)
5.  Mahrin Mahia (a1957342, mahrin.mahia@student.adelaide.edu.au)
6.  Maria Hasan Logno (a1975478, mariahasan.logno@student.adelaide.edu.au)

# Appendix

-   Peer review
-   Poc
-   SCOP
