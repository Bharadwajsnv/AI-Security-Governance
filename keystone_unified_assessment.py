"""Unified M3-M7 assessment orchestration for the Keystone capstone.

This module reuses the controls already implemented in keystone_engine.py.
It does not duplicate or replace the individual M3-M7 pages.
"""

from keystone_engine import (
    ACCESS_DENIED,
    ACCESS_GRANTED,
    AUTO_DIP,
    CREDIT_READ_SCOPE,
    CREDIT_TOOL_NAME,
    HUMAN_REVIEW,
    MCP_ALLOWED,
    ROLE_CUSTOMER_SERVICE,
    ROLE_UNDERWRITER,
    SECURITY_BLOCK,
    SUPPLY_CHAIN_ALLOWED,
    ActionPolicyEngine,
    EncryptionService,
    InjectionGuard,
    KeystoneRedTeamRegressionSuite,
    MCPToolRequest,
    MortgageApplication,
    SecureDataAccessService,
    SecureMCPGateway,
    SensitiveCustomerData,
    SupplyChainSecurityService,
    TamperEvidentAuditLog,
    ToolManifestService,
)


class KeystoneUnifiedAssessmentService:
    """Runs one application through the implemented M3-M7 controls."""

    @staticmethod
    def _customer_explanation(security_result, policy_result):
        if policy_result.decision == SECURITY_BLOCK:
            matched = ", ".join(security_result.matched_patterns)
            return (
                "Automated processing was stopped because the customer message "
                "contains configured prompt-injection indicators. "
                f"Detected indicators: {matched or 'configured security indicators'}. "
                "No automatic mortgage decision or downstream tool request was permitted."
            )

        if policy_result.decision == HUMAN_REVIEW:
            return (
                "The customer message passed the configured prompt-security check. "
                "However, the application is outside Keystone's automatic authority "
                "or requires non-standard underwriting. The request is legitimate, "
                "but it must be reviewed by a human underwriter."
            )

        if policy_result.decision == AUTO_DIP:
            return (
                "The customer message passed the configured prompt-security check, "
                "and the requested mortgage is within Keystone's trusted £500,000 "
                "automatic authority boundary."
            )

        return policy_result.reason

    @staticmethod
    def _control(control_id, name, status, category, summary, reason, evidence):
        return {
            "control_id": control_id,
            "control_name": name,
            "status": status,
            "category": category,
            "summary": summary,
            "reason": reason,
            "evidence": evidence,
        }

    @classmethod
    def run_full_assessment(
        cls,
        application: MortgageApplication,
        customer_message: str,
        run_full_regression: bool = True,
    ):
        controls = []

        # M3: application control
        security_result = InjectionGuard.scan(customer_message)
        m3_status = "BLOCKED" if security_result.detected else "PASS"
        controls.append(
            cls._control(
                "M3",
                "Prompt-Injection Protection",
                m3_status,
                "APPLICATION_CONTROL",
                (
                    "Configured malicious prompt indicators were detected."
                    if security_result.detected
                    else "The customer message passed the configured prompt-security check."
                ),
                security_result.reason,
                [
                    f"Risk level: {security_result.risk_level}",
                    f"Matched patterns: {security_result.matched_patterns}",
                    f"Input tested: {customer_message}",
                ],
            )
        )

        # M4: application control
        policy_result = ActionPolicyEngine.evaluate(
            application,
            security_alert=security_result.detected,
        )
        if security_result.detected:
            m4_status = "NOT_PROGRESSED"
            m4_summary = (
                "M3 stopped the journey before normal financial-authority progression."
            )
        elif policy_result.decision == HUMAN_REVIEW:
            m4_status = "HUMAN_REVIEW"
            m4_summary = (
                "The request is legitimate but outside automatic authority or requires "
                "non-standard underwriting."
            )
        elif policy_result.decision == AUTO_DIP:
            m4_status = "PASS"
            m4_summary = "The request is within the automatic authority boundary."
        else:
            m4_status = policy_result.decision
            m4_summary = policy_result.reason

        controls.append(
            cls._control(
                "M4",
                "Independent Mortgage Authority",
                m4_status,
                "APPLICATION_CONTROL",
                m4_summary,
                policy_result.reason,
                [
                    f"Requested mortgage: £{application.requested_amount:,.0f}",
                    f"Automatic limit: £{policy_result.auto_dip_limit:,.0f}",
                    f"Applicant type: {application.applicant_type}",
                    f"Policy decision: {policy_result.decision}",
                ],
            )
        )

        # Application audit evidence
        audit_log = TamperEvidentAuditLog()
        audit_log.add_event(
            event_type="APPLICATION_RECEIVED",
            application_id=application.application_id,
            message=(
                "Mortgage application received for "
                f"£{application.requested_amount:,.0f}."
            ),
            actor_role="KEYSTONE_APPLICATION",
        )
        audit_log.add_event(
            event_type="M3_SECURITY_CHECK",
            application_id=application.application_id,
            message=(
                f"Detected: {security_result.detected}. "
                f"Risk: {security_result.risk_level}. "
                f"Reason: {security_result.reason}"
            ),
            actor_role="INJECTION_GUARD",
        )
        audit_log.add_event(
            event_type="M4_POLICY_DECISION",
            application_id=application.application_id,
            message=(
                f"Requested £{application.requested_amount:,.0f}; "
                f"decision {policy_result.decision}; reason {policy_result.reason}"
            ),
            actor_role="ACTION_POLICY_ENGINE",
        )
        audit_log.add_event(
            event_type="FINAL_DECISION",
            application_id=application.application_id,
            message=f"Final Keystone decision: {policy_result.decision}.",
            actor_role="KEYSTONE_APPLICATION",
        )

        # M5 protected-data self-check
        encryption_service = EncryptionService()
        synthetic_customer = SensitiveCustomerData(
            application_id=application.application_id,
            national_insurance_number="QQ123456C",
            bank_account_number="12345678",
            sort_code="11-22-33",
            credit_score=application.credit_score,
        )
        encrypted_record = encryption_service.encrypt_customer_data(
            synthetic_customer
        )
        access_service = SecureDataAccessService(encryption_service)
        authorised = access_service.request_protected_data(
            encrypted_record=encrypted_record,
            requesting_role=ROLE_UNDERWRITER,
        )
        denied = access_service.request_protected_data(
            encrypted_record=encrypted_record,
            requesting_role=ROLE_CUSTOMER_SERVICE,
        )
        m5_data_verified = (
            authorised.status == ACCESS_GRANTED
            and authorised.data is not None
            and denied.status == ACCESS_DENIED
            and denied.data is None
        )
        controls.append(
            cls._control(
                "M5-DATA",
                "Protected Data and RBAC",
                "VERIFIED" if m5_data_verified else "FAIL",
                "PLATFORM_SELF_CHECK",
                (
                    "Encryption and role-based access behaved as expected using "
                    "synthetic protected data."
                    if m5_data_verified
                    else "The protected-data self-check did not match policy."
                ),
                (
                    "UNDERWRITER was granted access and CUSTOMER_SERVICE was denied "
                    "without receiving protected PII."
                    if m5_data_verified
                    else "One or more data-protection checks failed."
                ),
                [
                    f"UNDERWRITER: {authorised.status}",
                    f"CUSTOMER_SERVICE: {denied.status}",
                    f"Unauthorised PII returned: {denied.data is not None}",
                ],
            )
        )

        # M5 audit integrity
        audit_integrity = audit_log.verify_integrity()
        controls.append(
            cls._control(
                "M5-AUDIT",
                "Tamper-Evident Audit Integrity",
                "VALID" if audit_integrity["valid"] else "INVALID",
                "APPLICATION_EVIDENCE",
                (
                    "The application audit chain is valid."
                    if audit_integrity["valid"]
                    else "The application audit evidence failed integrity verification."
                ),
                audit_integrity["reason"],
                [
                    f"Audit events recorded: {len(audit_log.events)}",
                    f"Integrity valid: {audit_integrity['valid']}",
                    f"Failed event: {audit_integrity['event_id']}",
                ],
            )
        )

        # M6 MCP self-check. Short-circuit after malicious input.
        if security_result.detected:
            controls.append(
                cls._control(
                    "M6-MCP",
                    "Secure MCP Gateway",
                    "NOT_EXECUTED",
                    "PLATFORM_SELF_CHECK",
                    "No downstream tool request was permitted because M3 blocked the journey.",
                    "Secure short-circuit after prompt-injection detection.",
                    ["Tool executed: False", f"M3 status: {m3_status}"],
                )
            )
        else:
            gateway = SecureMCPGateway()
            manifest = ToolManifestService.build_credit_tool_manifest()
            mcp_request = MCPToolRequest(
                tool_name=CREDIT_TOOL_NAME,
                caller="KEYSTONE_AGENT",
                authenticated=True,
                scope=CREDIT_READ_SCOPE,
                application_id=application.application_id,
                requested_application_id=application.application_id,
                customer_reference=(
                    f"SYNTHETIC-{application.application_id}-CUSTOMER"
                ),
                purpose="mortgage_assessment",
            )
            mcp_result = gateway.execute_credit_request(
                request=mcp_request,
                current_manifest=manifest,
            )
            mcp_verified = (
                mcp_result.status == MCP_ALLOWED and mcp_result.tool_executed
            )
            controls.append(
                cls._control(
                    "M6-MCP",
                    "Secure MCP Gateway",
                    "VERIFIED" if mcp_verified else "FAIL",
                    "PLATFORM_SELF_CHECK",
                    (
                        "The authorised synthetic tool request passed all gateway checks."
                        if mcp_verified
                        else "The MCP gateway self-check failed."
                    ),
                    mcp_result.reason,
                    [
                        f"Authentication: {mcp_result.authentication_passed}",
                        f"Authorisation: {mcp_result.authorisation_passed}",
                        f"Scope: {mcp_result.scope_passed}",
                        f"Application boundary: {mcp_result.application_scope_passed}",
                        f"Argument security: {mcp_result.argument_security_passed}",
                        f"Manifest integrity: {mcp_result.manifest_integrity_passed}",
                        f"Tool executed: {mcp_result.tool_executed}",
                    ],
                )
            )

        # M6 supply-chain environment self-check
        approved_content = b"synthetic-keystone-mortgage-model-v1"
        approved_hash = SupplyChainSecurityService.calculate_artefact_hash(
            approved_content
        )
        supply_result = SupplyChainSecurityService.evaluate(
            artefact_name="mortgage_model.safetensors",
            artefact_content=approved_content,
            expected_hash=approved_hash,
            source="KEYSTONE_APPROVED_REGISTRY",
        )
        supply_verified = supply_result.status == SUPPLY_CHAIN_ALLOWED
        controls.append(
            cls._control(
                "M6-SUPPLY",
                "Supply-Chain Trust Gate",
                "VERIFIED" if supply_verified else "FAIL",
                "PLATFORM_SELF_CHECK",
                (
                    "The approved synthetic artefact passed format, source and integrity checks."
                    if supply_verified
                    else "The supply-chain self-check failed."
                ),
                supply_result.reason,
                [
                    f"Format allowed: {supply_result.format_allowed}",
                    f"Trusted source: {supply_result.source_trusted}",
                    f"Hash verified: {supply_result.hash_verified}",
                ],
            )
        )

        # M7 assurance
        red_team_suite = None
        if run_full_regression:
            red_team_suite = KeystoneRedTeamRegressionSuite.run_all()
            controls.append(
                cls._control(
                    "M7",
                    "Security Regression Gate",
                    "PASS" if red_team_suite.overall_status == "PASS" else "FAIL",
                    "SECURITY_ASSURANCE",
                    (
                        "The current RT-01 to RT-16 regression corpus passed."
                        if red_team_suite.overall_status == "PASS"
                        else "One or more defined regression scenarios failed."
                    ),
                    (
                        f"{red_team_suite.passed_tests} of "
                        f"{red_team_suite.total_tests} tests passed."
                    ),
                    [
                        f"Tests executed: {red_team_suite.total_tests}",
                        f"Passed: {red_team_suite.passed_tests}",
                        f"Failed: {red_team_suite.failed_tests}",
                        f"Critical failures: {red_team_suite.critical_failures}",
                    ],
                )
            )
        else:
            controls.append(
                cls._control(
                    "M7",
                    "Security Regression Gate",
                    "NOT_EXECUTED",
                    "SECURITY_ASSURANCE",
                    "Full security regression was not requested for this assessment.",
                    "M7 normally runs on demand, during release assurance or after material changes.",
                    [],
                )
            )

        failed = [c for c in controls if c["status"] in {"FAIL", "INVALID"}]
        if failed:
            platform_status = "SECURITY_CONTROL_FAILURE"
        elif policy_result.decision == SECURITY_BLOCK:
            platform_status = "ATTACK_DETECTED_AND_CONTAINED"
        else:
            platform_status = "ALL_EXECUTED_CONTROLS_HEALTHY"

        return {
            "application_id": application.application_id,
            "application_outcome": policy_result.decision,
            "customer_explanation": cls._customer_explanation(
                security_result,
                policy_result,
            ),
            "platform_security_status": platform_status,
            "message_under_test": customer_message,
            "controls": controls,
            "audit_log": audit_log,
            "red_team_suite": red_team_suite,
            "security_result": security_result,
            "policy_result": policy_result,
        }
