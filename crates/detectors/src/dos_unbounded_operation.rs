use anyhow::Result;
use std::any::Any;

use crate::detector::{BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils::is_deployment_tooling;

/// Detector for DOS via unbounded operations
pub struct DosUnboundedOperationDetector {
    base: BaseDetector,
}

impl Default for DosUnboundedOperationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DosUnboundedOperationDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId("dos-unbounded-operation".to_string()),
                "DOS via Unbounded Operation".to_string(),
                "Detects unbounded loops and operations that can cause denial of service"
                    .to_string(),
                vec![DetectorCategory::Logic],
                Severity::High,
            ),
        }
    }
}

impl Detector for DosUnboundedOperationDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn is_enabled(&self) -> bool {
        self.base.enabled
    }

    fn detect(&self, ctx: &AnalysisContext<'_>) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        // FP Reduction: Skip interface contracts (no implementation to exploit)
        if crate::utils::is_interface_contract(ctx) {
            return Ok(findings);
        }

        // FP Reduction: Skip library contracts (cannot hold state or receive Ether)
        if crate::utils::is_library_contract(ctx) {
            return Ok(findings);
        }

        // Phase 16 FP Reduction: Skip deployment tooling files
        if is_deployment_tooling(ctx) {
            return Ok(findings);
        }

        for function in ctx.get_functions() {
            if let Some(dos_issue) = self.check_unbounded_operation(function, ctx) {
                let message = format!(
                    "Function '{}' has DOS vulnerability via unbounded operation. {} \
                    Can cause out-of-gas errors blocking contract functionality.",
                    function.name.name, dos_issue
                );

                let finding = self
                    .base
                    .create_finding(
                        ctx,
                        message,
                        function.name.location.start().line() as u32,
                        function.name.location.start().column() as u32,
                        function.name.name.len() as u32,
                    )
                    .with_cwe(834) // CWE-834: Excessive Iteration
                    .with_cwe(400) // CWE-400: Uncontrolled Resource Consumption
                    .with_fix_suggestion(format!(
                        "Fix unbounded operation in '{}'. \
                    Add pagination for large loops, implement maximum iteration limits, \
                    use pull pattern instead of push, add circuit breakers, batch operations.",
                        function.name.name
                    ));

                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl DosUnboundedOperationDetector {
    fn check_unbounded_operation(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
    ) -> Option<String> {
        function.body.as_ref()?;

        // FP Reduction: Constructors execute only once at deployment and cannot
        // cause runtime DOS. Loops in constructors over calldata/memory arrays
        // are a standard initialization pattern (e.g., setting supported tokens).
        if function.function_type == ast::FunctionType::Constructor {
            return None;
        }

        let func_source = self.get_function_source(function, ctx);
        let func_name_lower = function.name.name.to_lowercase();

        // Phase 16 FP Reduction: Skip safe enumeration patterns
        if self.is_safe_enumeration(ctx, &func_name_lower) {
            return None;
        }

        // Phase 54 FP Reduction: Skip view/pure functions with pagination parameters
        if self.is_paginated_view_function(function, &func_source) {
            return None;
        }

        // Phase 54 FP Reduction: Skip multicall patterns with size validation
        if self.is_safe_multicall_pattern(&func_source) {
            return None;
        }

        // Phase 54 FP Reduction: Skip admin-only view functions
        if self.is_admin_only_view(function, ctx) {
            return None;
        }

        // FP Reduction: Pure/internal functions operating on memory arrays are
        // bounded by caller input, not by unbounded storage growth. These include
        // sort(), median(), verifyMerkleProof(), etc.
        if self.is_bounded_memory_operation(function, &func_source) {
            return None;
        }

        // FP Reduction: View functions in standard patterns (Diamond Loupe, etc.)
        // that iterate over admin-managed arrays are bounded by design.
        if self.is_standard_view_pattern(function, ctx, &func_name_lower) {
            return None;
        }

        // Pattern 1: Loop over unbounded array
        let has_loop = ["for (", "for(", "while (", "while("]
            .iter()
            .any(|kw| func_source.contains(kw));
        let loops_over_storage =
            has_loop && (func_source.contains(".length") || func_source.contains("[]"));

        // Phase 16 FP Reduction: Improved bounds detection
        let has_iteration_bound = loops_over_storage && self.has_iteration_bound(&func_source);

        // FP Reduction: Check if loops only iterate over calldata/memory parameters
        // rather than storage arrays. Calldata/memory arrays are caller-bounded.
        let only_loops_over_params =
            loops_over_storage && self.loops_only_over_parameters(function, &func_source);

        let no_iteration_limit = loops_over_storage
            && !has_iteration_bound
            && !only_loops_over_params
            && !func_source.contains("MAX_")
            && !func_source.contains("require(")
            && !func_source.contains("<=");

        if no_iteration_limit {
            return Some(
                "Loop over unbounded array without iteration limit, \
                large arrays cause out-of-gas"
                    .to_string(),
            );
        }

        // Pattern 2: Deleting large structures
        // Phase 16 FP Reduction: Only flag if no bound check
        if func_source.contains("delete") && func_source.contains("[") {
            // Check if there's a bound on what's being deleted
            if !self.has_delete_bound(&func_source) {
                return Some(
                    "Deleting array or mapping without size limit, \
                    can exceed gas limit"
                        .to_string(),
                );
            }
        }

        None
    }

    /// Phase 16 FP Reduction: Check if loop has iteration bounds
    fn has_iteration_bound(&self, loop_source: &str) -> bool {
        // Detect MAX constant bounds
        let has_max_constant = loop_source.contains("MAX_")
            || loop_source.contains("_MAX")
            || loop_source.contains("LIMIT")
            || loop_source.contains("_LIMIT");

        if has_max_constant {
            return true;
        }

        // Detect min() bounds - common in OpenZeppelin
        if loop_source.contains("min(") || loop_source.contains("Math.min(") {
            return true;
        }

        // Detect hardcoded numeric limits (e.g., i < 100)
        // Look for comparison with a number >= 10
        let numeric_patterns = [
            "< 10", "< 20", "< 50", "< 100", "< 256", "< 1000", "<= 10", "<= 20", "<= 50",
            "<= 100", "<= 256", "<= 1000", "> 0 &&", ">= 1 &&", // combined with other checks
        ];

        for pattern in &numeric_patterns {
            if loop_source.contains(pattern) {
                return true;
            }
        }

        // Detect batch size patterns
        if loop_source.contains("batchSize")
            || loop_source.contains("batch_size")
            || loop_source.contains("chunkSize")
            || loop_source.contains("pageSize")
        {
            return true;
        }

        false
    }

    /// Phase 16 FP Reduction: Check if delete operation has bounds
    fn has_delete_bound(&self, func_source: &str) -> bool {
        // Single element delete is safe
        if func_source.contains("delete ") && !func_source.contains("delete []") {
            // Check if it's a loop delete with bounds
            if func_source.contains("for") && self.has_iteration_bound(func_source) {
                return true;
            }
            // Single element delete
            return true;
        }

        false
    }

    /// Phase 16 FP Reduction: Check if this is a safe enumeration pattern
    fn is_safe_enumeration(&self, ctx: &AnalysisContext, func_name: &str) -> bool {
        let source = &ctx.source_code;

        // AccessControl role enumeration is by design (bounded by role count)
        if source.contains("AccessControl") || source.contains("IAccessControl") {
            if func_name.contains("getrolemember")
                || func_name.contains("enumerate")
                || func_name.contains("getrolemembercount")
            {
                return true;
            }
        }

        // EnumerableSet/Map iterations are bounded by set size
        if source.contains("EnumerableSet") || source.contains("EnumerableMap") {
            if func_name.contains("values")
                || func_name.contains("keys")
                || func_name.contains("at(")
            {
                return true;
            }
        }

        // View functions that enumerate are often getter patterns
        if func_name.contains("getall") || func_name.contains("list") {
            // Check if it's a view function
            if source.contains(&format!("function {}(", func_name)) && source.contains("view") {
                return true;
            }
        }

        false
    }

    fn get_function_source(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> String {
        let start = function.location.start().line();
        let end = function.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
    }

    /// Phase 54 FP Reduction: Check if function is a view/pure with pagination parameters
    fn is_paginated_view_function(&self, function: &ast::Function<'_>, func_source: &str) -> bool {
        // Must be view or pure
        if function.mutability != ast::StateMutability::View
            && function.mutability != ast::StateMutability::Pure
        {
            return false;
        }

        let func_lower = func_source.to_lowercase();

        // Check for pagination parameters
        func_lower.contains("offset")
            || func_lower.contains("limit")
            || func_lower.contains("start")
            || func_lower.contains("count")
            || func_lower.contains("pagesize")
            || func_lower.contains("page_size")
            || func_lower.contains("skip")
            || func_lower.contains("take")
    }

    /// Phase 54 FP Reduction: Check if this is a safe multicall pattern with size validation
    fn is_safe_multicall_pattern(&self, func_source: &str) -> bool {
        let func_lower = func_source.to_lowercase();

        // Check if it's a multicall pattern
        let is_multicall = func_lower.contains("multicall")
            || func_lower.contains("batch")
            || func_lower.contains("aggregate");

        if !is_multicall {
            return false;
        }

        // Check for size validation
        let has_size_check = func_lower.contains("require(")
            && (func_lower.contains(".length")
                && (func_lower.contains("<=") || func_lower.contains("<")))
            || func_lower.contains("max_")
            || func_lower.contains("_max")
            || func_lower.contains("maxcalls")
            || func_lower.contains("max_calls");

        // Check for Math.min usage in loop bounds
        let has_min_bound = func_lower.contains("math.min(")
            || func_lower.contains(".min(")
            || (func_lower.contains("min(") && func_lower.contains("length"));

        has_size_check || has_min_bound
    }

    /// Phase 54 FP Reduction: Check if function is an admin-only view function
    fn is_admin_only_view(&self, function: &ast::Function<'_>, ctx: &AnalysisContext) -> bool {
        // Must be view or pure
        if function.mutability != ast::StateMutability::View
            && function.mutability != ast::StateMutability::Pure
        {
            return false;
        }

        // Check for access control modifiers
        let has_admin_modifier = function.modifiers.iter().any(|m| {
            let name_lower = m.name.name.to_lowercase();
            name_lower.contains("owner")
                || name_lower.contains("admin")
                || name_lower.contains("only")
                || name_lower.contains("authorized")
        });

        if has_admin_modifier {
            return true;
        }

        // Check for inline access control in source
        let func_source = self.get_function_source(function, ctx);
        let has_inline_check = func_source.contains("require(msg.sender")
            || func_source.contains("require(hasRole")
            || func_source.contains("if (msg.sender");

        has_inline_check
    }

    /// FP Reduction: Check if function operates only on memory/calldata arrays
    /// (not storage arrays). Pure functions and internal functions that take
    /// memory/calldata array parameters and loop over them are bounded by the
    /// caller's input, not by unbounded storage growth.
    fn is_bounded_memory_operation(&self, function: &ast::Function<'_>, func_source: &str) -> bool {
        // Pure functions cannot read storage, so any loop is over memory/calldata
        if function.mutability == ast::StateMutability::Pure {
            return true;
        }

        // Internal/private functions with memory/calldata array params that loop
        // over those params are caller-bounded
        if function.visibility == ast::Visibility::Internal
            || function.visibility == ast::Visibility::Private
        {
            let has_array_param = function.parameters.iter().any(|p| {
                matches!(
                    p.storage_location,
                    Some(ast::StorageLocation::Memory) | Some(ast::StorageLocation::Calldata)
                ) && self.param_type_is_array(p, func_source)
            });

            if has_array_param && self.loops_only_over_parameters(function, func_source) {
                return true;
            }
        }

        false
    }

    /// Check if a parameter type is an array type by examining its source
    fn param_type_is_array(&self, param: &ast::Parameter<'_>, func_source: &str) -> bool {
        // Check parameter name appears with .length in the source
        if let Some(ref name) = param.name {
            let length_access = format!("{}.length", name.name);
            if func_source.contains(&length_access) {
                return true;
            }
        }
        // Also check storage location hints - calldata/memory with [] in source
        // near the parameter signature
        true // Conservative: if it has memory/calldata location, treat as potential array
    }

    /// Check if loops in the function only iterate over function parameters
    /// (calldata/memory) rather than storage state variables.
    fn loops_only_over_parameters(&self, function: &ast::Function<'_>, func_source: &str) -> bool {
        // Collect parameter names that are memory/calldata arrays
        let param_names: Vec<&str> = function
            .parameters
            .iter()
            .filter(|p| {
                matches!(
                    p.storage_location,
                    Some(ast::StorageLocation::Memory) | Some(ast::StorageLocation::Calldata)
                )
            })
            .filter_map(|p| p.name.as_ref().map(|n| n.name))
            .collect();

        if param_names.is_empty() {
            return false;
        }

        // Find all .length references in loops and check if they come from params
        // Look for patterns like: i < paramName.length or i < localVar where
        // localVar = paramName.length
        let length_refs: Vec<&str> = func_source.split(".length").collect::<Vec<_>>();

        if length_refs.len() <= 1 {
            return false; // No .length references
        }

        // Check each .length reference (except the last split part which is after the last .length)
        for i in 0..length_refs.len() - 1 {
            let before_length = length_refs[i];
            // Get the identifier before .length
            let ident: String = before_length
                .chars()
                .rev()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect::<String>()
                .chars()
                .rev()
                .collect();

            if ident.is_empty() {
                continue;
            }

            // Skip assignments TO `.length` (e.g. a struct field write like
            // `plan.length = ...`). A write target is not a loop bound.
            let after = length_refs[i + 1].trim_start();
            if after.starts_with('=') && !after.starts_with("==") {
                continue;
            }

            // Check if this identifier is a parameter name or a local variable
            // derived from a parameter
            let is_param = param_names.iter().any(|&pn| pn == ident);
            if is_param {
                continue; // This .length is from a parameter, safe
            }

            // Check if the identifier is a local variable assigned from a param
            // e.g., uint256 numItems = data.length; ... i < numItems
            let local_assign_pattern = format!("{} = ", ident);
            if let Some(assign_pos) = func_source.find(&local_assign_pattern) {
                let after_assign = &func_source[assign_pos + local_assign_pattern.len()..];
                let assigned_from: String = after_assign
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '.')
                    .collect();
                let is_from_param = param_names.iter().any(|&pn| assigned_from.starts_with(pn));
                if is_from_param {
                    continue; // Local var derived from param, safe
                }
            }

            // This .length reference is from a storage variable -- not safe
            return false;
        }

        true
    }

    /// FP Reduction: Check if this is a standard view pattern that iterates over
    /// admin-managed or inherently bounded data structures.
    fn is_standard_view_pattern(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext,
        func_name: &str,
    ) -> bool {
        // Must be view or pure
        if function.mutability != ast::StateMutability::View
            && function.mutability != ast::StateMutability::Pure
        {
            return false;
        }

        let source = &ctx.source_code;

        // EIP-2535 Diamond Loupe pattern: facets(), facetAddresses(), etc.
        // These iterate over admin-managed facet lists that are bounded by
        // the number of diamond cuts (typically small).
        if source.contains("IDiamondLoupe") || source.contains("DiamondLoupe") {
            if func_name == "facets"
                || func_name == "facetaddresses"
                || func_name == "facetfunctionselectors"
            {
                return true;
            }
        }

        // ERC-165 supportsInterface enumeration patterns
        if func_name.contains("supportsinterface") || func_name.contains("getinterfaces") {
            return true;
        }

        // Merkle proof verification: loops are bounded by tree depth (log2(n))
        if func_name.contains("merkle") || func_name.contains("proof") {
            let func_source = self.get_function_source(function, ctx);
            // Merkle proofs iterate over proof elements (typically <= 32 for trees up to 2^32)
            if func_source.contains("keccak256") || func_source.contains("hash") {
                return true;
            }
        }

        false
    }

    /// Phase 54 FP Reduction: Check if contract uses EnumerableSet/EnumerableMap
    #[allow(dead_code)]
    fn uses_enumerable_library(&self, ctx: &AnalysisContext) -> bool {
        let source = &ctx.source_code;

        source.contains("EnumerableSet")
            || source.contains("EnumerableMap")
            || source.contains("using EnumerableSet")
            || source.contains("using EnumerableMap")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detector_properties() {
        let detector = DosUnboundedOperationDetector::new();
        assert_eq!(detector.name(), "DOS via Unbounded Operation");
        assert_eq!(detector.default_severity(), Severity::High);
        assert!(detector.is_enabled());
    }

    #[test]
    fn test_has_iteration_bound_max_constant() {
        let detector = DosUnboundedOperationDetector::new();
        assert!(detector.has_iteration_bound("for (uint i = 0; i < MAX_ITERATIONS; i++)"));
        assert!(detector.has_iteration_bound("for (uint i = 0; i < items_MAX; i++)"));
        assert!(detector.has_iteration_bound("require(items.length < LIMIT)"));
        assert!(detector.has_iteration_bound("require(items.length < GAS_LIMIT)"));
    }

    #[test]
    fn test_has_iteration_bound_min_function() {
        let detector = DosUnboundedOperationDetector::new();
        assert!(detector.has_iteration_bound("uint end = min(start + batchSize, items.length)"));
        assert!(
            detector.has_iteration_bound("uint end = Math.min(start + batchSize, items.length)")
        );
    }

    #[test]
    fn test_has_iteration_bound_numeric_limits() {
        let detector = DosUnboundedOperationDetector::new();
        assert!(detector.has_iteration_bound("for (uint i = 0; i < 100; i++)"));
        assert!(detector.has_iteration_bound("for (uint i = 0; i < 256; i++)"));
        assert!(detector.has_iteration_bound("for (uint i = 0; i <= 50; i++)"));
    }

    #[test]
    fn test_has_iteration_bound_batch_size() {
        let detector = DosUnboundedOperationDetector::new();
        assert!(detector.has_iteration_bound("uint end = start + batchSize"));
        assert!(detector.has_iteration_bound("uint end = start + pageSize"));
    }

    #[test]
    fn test_has_iteration_bound_no_bound() {
        let detector = DosUnboundedOperationDetector::new();
        assert!(
            !detector.has_iteration_bound(
                "for (uint i = 0; i < items.length; i++) { process(items[i]); }"
            )
        );
    }

    #[test]
    fn test_has_delete_bound_single_element() {
        let detector = DosUnboundedOperationDetector::new();
        assert!(detector.has_delete_bound("delete items[index];"));
    }

    #[test]
    fn test_has_delete_bound_no_bound() {
        let detector = DosUnboundedOperationDetector::new();
        assert!(!detector.has_delete_bound("delete []items;"));
    }

    #[test]
    fn test_is_safe_multicall_with_size_check() {
        let detector = DosUnboundedOperationDetector::new();
        assert!(detector.is_safe_multicall_pattern(
            "function multicall(bytes[] calldata data) external {\n\
             require(data.length <= MAX_CALLS);\n\
             for (uint i = 0; i < data.length; i++) {}"
        ));
    }

    #[test]
    fn test_is_safe_multicall_without_size_check() {
        let detector = DosUnboundedOperationDetector::new();
        // multicall without any size validation is not safe
        assert!(!detector.is_safe_multicall_pattern(
            "function multicall(bytes[] calldata data) external {\n\
             for (uint i = 0; i < data.length; i++) {}"
        ));
    }

    #[test]
    fn test_is_safe_multicall_non_multicall() {
        let detector = DosUnboundedOperationDetector::new();
        assert!(
            !detector.is_safe_multicall_pattern(
                "function transfer(address to, uint amount) external {}"
            )
        );
    }

    #[test]
    fn test_loops_only_over_parameters_source_matching() {
        let detector = DosUnboundedOperationDetector::new();
        // Test the raw source parsing logic by checking the .length extraction
        let source = "for (uint i = 0; i < tokens.length; i++) { process(tokens[i]); }";
        let parts: Vec<&str> = source.split(".length").collect();
        assert_eq!(parts.len(), 2); // One .length reference

        let before = parts[0];
        let ident: String = before
            .chars()
            .rev()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        assert_eq!(ident, "tokens");
    }
}
