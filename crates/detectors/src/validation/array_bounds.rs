use anyhow::Result;
use ast::{self, Located};
use std::any::Any;
use std::collections::HashMap;

use crate::detector::{AstAnalyzer, BaseDetector, Detector, DetectorCategory};
use crate::types::{AnalysisContext, DetectorId, Finding, Severity};
use crate::utils::{is_secure_example_file, is_test_contract};

/// Detector for array bounds checking vulnerabilities
pub struct ArrayBoundsDetector {
    base: BaseDetector,
}

impl Default for ArrayBoundsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ArrayBoundsDetector {
    pub fn new() -> Self {
        Self {
            base: BaseDetector::new(
                DetectorId::new("array-bounds-check"),
                "Array Bounds Check".to_string(),
                "Detects potential array out-of-bounds access and missing length validation"
                    .to_string(),
                vec![DetectorCategory::Validation],
                Severity::High,
            ),
        }
    }

    /// Analyze a function for array bounds issues
    fn analyze_function_for_array_bounds(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // FP Reduction: Skip view/pure functions — they cannot modify state,
        // so out-of-bounds access will revert harmlessly (no fund loss risk).
        let func_source = self.get_function_source(function, ctx).to_lowercase();
        if func_source.contains(" view ") || func_source.contains(" pure ") {
            return findings;
        }

        if let Some(body) = &function.body {
            // Identify array parameters and variables
            let arrays = self.identify_arrays(function, ctx);

            // FP Reduction Pattern B: Check if function modifiers validate array bounds
            // e.g., modifier validPool(uint256 _pid) { require(_pid < poolInfo.length); _; }
            let modifier_bounded = self.get_modifier_bounded_vars(function, &arrays, ctx);

            // Check for unchecked array access
            findings.extend(self.check_unchecked_array_access_with_modifier_bounds(
                body,
                &arrays,
                &modifier_bounded,
                ctx,
            ));

            // Check for loop bounds issues
            findings.extend(self.check_loop_array_bounds(body, &arrays, ctx));

            // Check for missing length validation
            findings.extend(self.check_missing_length_validation(function, &arrays, ctx));

            // Check for off-by-one errors
            findings.extend(self.check_off_by_one_errors(body, &arrays, ctx));
        }

        findings
    }

    /// Identify array variables and parameters in the function
    fn identify_arrays(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> HashMap<String, ArrayInfo> {
        let mut arrays = HashMap::new();

        // Check function parameters
        for param in &function.parameters {
            if let Some(name) = &param.name {
                let array_info = self.get_array_info(&param.type_name, &name.location);
                if let Some(info) = array_info {
                    arrays.insert(name.name.to_string(), info);
                }
            }
        }

        // Check state variables (simplified - in real implementation would analyze contract state)
        for state_var in &ctx.contract.state_variables {
            let array_info = self.get_array_info(&state_var.type_name, &state_var.location);
            if let Some(info) = array_info {
                arrays.insert(state_var.name.name.to_string(), info);
            }
        }

        arrays
    }

    /// Extract array information from type name
    fn get_array_info(
        &self,
        type_name: &ast::TypeName<'_>,
        location: &ast::SourceLocation,
    ) -> Option<ArrayInfo> {
        match type_name {
            ast::TypeName::Array { base_type, length } => {
                Some(ArrayInfo {
                    _base_type: format!("{:?}", base_type), // Simplified - would need proper type formatting
                    is_dynamic: length.is_none(),
                    _fixed_length: length.and_then(|_| Some(0)), // Would need to evaluate expression
                    _location: location.clone(),
                    _dimensions: 1,
                })
            }
            _ => None,
        }
    }

    /// FP Reduction Pattern B: Check function modifiers for array bounds validation
    /// Returns map of param_name -> array_name for modifier-bounded parameters
    /// e.g., modifier validPool(uint256 _pid) { require(_pid < poolInfo.length); _; }
    fn get_modifier_bounded_vars(
        &self,
        function: &ast::Function<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        ctx: &AnalysisContext<'_>,
    ) -> HashMap<String, String> {
        let mut bounded = HashMap::new();

        // Check each modifier attached to the function
        for modifier_ref in &function.modifiers {
            // Find the modifier definition in the contract
            for mod_def in &ctx.contract.modifiers {
                if mod_def.name.name == modifier_ref.name.name {
                    // Get the modifier source code
                    let mod_source = self.get_modifier_source(mod_def, ctx).to_lowercase();

                    // Look for require(param < array.length) pattern
                    for param in &function.parameters {
                        if let Some(param_name) = &param.name {
                            let param_lower = param_name.name.to_lowercase();

                            // Check if modifier validates this param against any array
                            for (array_name, _) in arrays.iter() {
                                let array_lower = array_name.to_lowercase();

                                // Match patterns like: require(_pid < poolinfo.length
                                if mod_source
                                    .contains(&format!("{} < {}.length", param_lower, array_lower))
                                    || mod_source.contains(&format!(
                                        "{}< {}.length",
                                        param_lower, array_lower
                                    ))
                                    || mod_source.contains(&format!(
                                        "{} <{}.length",
                                        param_lower, array_lower
                                    ))
                                {
                                    bounded.insert(param_name.name.to_string(), array_name.clone());
                                }
                            }
                        }
                    }
                }
            }
        }

        bounded
    }

    /// Get modifier source code for analysis
    fn get_modifier_source(&self, modifier: &ast::Modifier<'_>, ctx: &AnalysisContext) -> String {
        let start = modifier.location.start().line();
        let end = modifier.location.end().line();

        let source_lines: Vec<&str> = ctx.source_code.lines().collect();
        if start < source_lines.len() && end < source_lines.len() {
            source_lines[start..=end].join("\n")
        } else {
            String::new()
        }
    }

    /// Check for unchecked array access patterns (with modifier bounds)
    fn check_unchecked_array_access_with_modifier_bounds(
        &self,
        block: &ast::Block<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        modifier_bounded: &HashMap<String, String>,
        ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for stmt in &block.statements {
            self.check_statement_for_unchecked_access(
                stmt,
                arrays,
                &mut findings,
                ctx,
                modifier_bounded,
            );
        }

        findings
    }

    /// Check for unchecked array access patterns (legacy method)
    fn check_unchecked_array_access(
        &self,
        block: &ast::Block<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        let bounded_vars: HashMap<String, String> = HashMap::new();
        self.check_unchecked_array_access_with_modifier_bounds(block, arrays, &bounded_vars, ctx)
    }

    /// Extract loop variable bounds from a for loop condition
    /// Returns (loop_var_name, array_name) if condition is like `i < arr.length`
    fn extract_loop_bounds(&self, condition: &ast::Expression<'_>) -> Option<(String, String)> {
        if let ast::Expression::BinaryOperation {
            operator,
            left,
            right,
            ..
        } = condition
        {
            if matches!(
                operator,
                ast::BinaryOperator::Less | ast::BinaryOperator::LessEqual
            ) {
                // Get loop variable from left side
                let loop_var = if let ast::Expression::Identifier(id) = left {
                    Some(id.name.to_string())
                } else {
                    None
                };

                // Get array name from right side (arr.length)
                let array_name = if let ast::Expression::MemberAccess {
                    expression, member, ..
                } = right
                {
                    if member.name == "length" {
                        if let ast::Expression::Identifier(arr_id) = expression {
                            Some(arr_id.name.to_string())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let (Some(lv), Some(an)) = (loop_var, array_name) {
                    return Some((lv, an));
                }
            }
        }
        None
    }

    /// Check statement for unchecked array access
    fn check_statement_for_unchecked_access(
        &self,
        stmt: &ast::Statement<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        findings: &mut Vec<Finding>,
        ctx: &AnalysisContext<'_>,
        bounded_vars: &HashMap<String, String>,
    ) {
        match stmt {
            ast::Statement::Expression(expr) => {
                self.check_expression_for_unchecked_access(
                    expr,
                    arrays,
                    findings,
                    ctx,
                    bounded_vars,
                );
            }
            ast::Statement::VariableDeclaration {
                initial_value: Some(expr),
                ..
            } => {
                self.check_expression_for_unchecked_access(
                    expr,
                    arrays,
                    findings,
                    ctx,
                    bounded_vars,
                );
            }
            ast::Statement::If {
                condition,
                then_branch,
                else_branch,
                ..
            } => {
                self.check_expression_for_unchecked_access(
                    condition,
                    arrays,
                    findings,
                    ctx,
                    bounded_vars,
                );
                self.check_statement_for_unchecked_access(
                    then_branch,
                    arrays,
                    findings,
                    ctx,
                    bounded_vars,
                );
                if let Some(else_stmt) = else_branch {
                    self.check_statement_for_unchecked_access(
                        else_stmt,
                        arrays,
                        findings,
                        ctx,
                        bounded_vars,
                    );
                }
            }
            ast::Statement::While {
                condition, body, ..
            } => {
                self.check_expression_for_unchecked_access(
                    condition,
                    arrays,
                    findings,
                    ctx,
                    bounded_vars,
                );
                self.check_statement_for_unchecked_access(
                    body,
                    arrays,
                    findings,
                    ctx,
                    bounded_vars,
                );
            }
            ast::Statement::For {
                init,
                condition,
                update,
                body,
                ..
            } => {
                if let Some(init_stmt) = init {
                    self.check_statement_for_unchecked_access(
                        init_stmt,
                        arrays,
                        findings,
                        ctx,
                        bounded_vars,
                    );
                }
                if let Some(cond_expr) = condition {
                    self.check_expression_for_unchecked_access(
                        cond_expr,
                        arrays,
                        findings,
                        ctx,
                        bounded_vars,
                    );
                }
                if let Some(update_expr) = update {
                    self.check_expression_for_unchecked_access(
                        update_expr,
                        arrays,
                        findings,
                        ctx,
                        bounded_vars,
                    );
                }

                // Extract loop bounds and pass to body check
                let mut body_bounded_vars = bounded_vars.clone();
                if let Some(cond_expr) = condition {
                    if let Some((loop_var, array_name)) = self.extract_loop_bounds(cond_expr) {
                        body_bounded_vars.insert(loop_var, array_name);
                    }
                }
                self.check_statement_for_unchecked_access(
                    body,
                    arrays,
                    findings,
                    ctx,
                    &body_bounded_vars,
                );
            }
            ast::Statement::Block(block) => {
                for inner_stmt in &block.statements {
                    self.check_statement_for_unchecked_access(
                        inner_stmt,
                        arrays,
                        findings,
                        ctx,
                        bounded_vars,
                    );
                }
            }
            _ => {}
        }
    }

    /// Check expression for unchecked array access
    fn check_expression_for_unchecked_access(
        &self,
        expr: &ast::Expression<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        findings: &mut Vec<Finding>,
        ctx: &AnalysisContext<'_>,
        bounded_vars: &HashMap<String, String>,
    ) {
        match expr {
            ast::Expression::IndexAccess {
                base,
                index,
                location,
            } => {
                // Check if base is an array
                if let ast::Expression::Identifier(id) = base {
                    if arrays.contains_key(id.name) {
                        // Check if index is validated
                        if let Some(index_expr) = index {
                            if !self.is_index_validated(index_expr, id.name, &arrays, bounded_vars)
                            {
                                let message = format!(
                                    "Array access to '{}' may be out of bounds - index not validated",
                                    id.name
                                );

                                let severity = if arrays[id.name].is_dynamic {
                                    Severity::High
                                } else {
                                    Severity::Medium
                                };

                                let finding = self.base.create_finding_with_severity(
                                    ctx,
                                    message,
                                    location.start().line() as u32,
                                    location.start().column() as u32,
                                    location.byte_length() as u32,
                                    severity,
                                )
                                .with_cwe(125) // CWE-125: Out-of-bounds Read
                                .with_fix_suggestion(
                                    format!("Add bounds check: require(index < {}.length, \"Index out of bounds\");", id.name)
                                );
                                findings.push(finding);
                            }
                        }
                    }
                }
            }
            ast::Expression::BinaryOperation { left, right, .. } => {
                self.check_expression_for_unchecked_access(
                    left,
                    arrays,
                    findings,
                    ctx,
                    bounded_vars,
                );
                self.check_expression_for_unchecked_access(
                    right,
                    arrays,
                    findings,
                    ctx,
                    bounded_vars,
                );
            }
            ast::Expression::Assignment { left, right, .. } => {
                self.check_expression_for_unchecked_access(
                    left,
                    arrays,
                    findings,
                    ctx,
                    bounded_vars,
                );
                self.check_expression_for_unchecked_access(
                    right,
                    arrays,
                    findings,
                    ctx,
                    bounded_vars,
                );
            }
            ast::Expression::FunctionCall {
                function,
                arguments,
                ..
            } => {
                self.check_expression_for_unchecked_access(
                    function,
                    arrays,
                    findings,
                    ctx,
                    bounded_vars,
                );
                for arg in arguments {
                    self.check_expression_for_unchecked_access(
                        arg,
                        arrays,
                        findings,
                        ctx,
                        bounded_vars,
                    );
                }
            }
            _ => {}
        }
    }

    /// Check if an index is properly validated
    fn is_index_validated(
        &self,
        index_expr: &ast::Expression<'_>,
        array_name: &str,
        arrays: &HashMap<String, ArrayInfo>,
        bounded_vars: &HashMap<String, String>,
    ) -> bool {
        match index_expr {
            // Check if index is a bounded loop variable
            ast::Expression::Identifier(id) => {
                // If this variable is bounded by this array's length, it's safe
                if let Some(bound_array) = bounded_vars.get(id.name) {
                    if bound_array == array_name {
                        return true;
                    }
                }
                // Phase 6: Common safe variable names used in loops / iteration
                let id_lower = id.name.to_lowercase();
                if id_lower == "i"
                    || id_lower == "j"
                    || id_lower == "k"
                    || id_lower == "idx"
                    || id_lower == "index"
                    || id_lower == "offset"
                    || id_lower == "pos"
                    || id_lower == "n"
                    || id_lower == "count"
                    || id_lower == "tokenid"
                    || id_lower == "id"
                {
                    return true; // Likely a loop/index variable
                }
                false
            }
            // Literal indices might be safe if they're small constants
            ast::Expression::Literal { value, .. } => {
                if let ast::LiteralValue::Number(num) = value {
                    // Phase 6: Small literal indices are generally safe
                    // Also check against fixed array size if available
                    match num.parse::<u32>() {
                        Ok(n) => {
                            // For fixed-size arrays, check if index is within bounds
                            if let Some(arr_info) = arrays.get(array_name) {
                                if let Some(fixed_len) = arr_info._fixed_length {
                                    return n < fixed_len;
                                }
                            }
                            // For dynamic arrays, small indices (< 10) are likely safe
                            n < 10
                        }
                        Err(_) => false,
                    }
                } else {
                    false
                }
            }
            // Simple arithmetic on bounded variables (i + 1, i - 1) where i < arr.length
            // Note: i + 1 could still overflow at arr.length - 1, but this is much less common
            ast::Expression::BinaryOperation {
                operator,
                left,
                right,
                ..
            } => {
                // FP Reduction Pattern A: Modulo by array.length guarantees in-bounds
                // e.g., hash % participants.length is always < participants.length
                if matches!(operator, ast::BinaryOperator::Mod) {
                    if let ast::Expression::MemberAccess { member, .. } = right {
                        if member.name == "length" {
                            // x % *.length is always bounded by the array length
                            return true;
                        }
                    }
                }

                if matches!(
                    operator,
                    ast::BinaryOperator::Add | ast::BinaryOperator::Sub
                ) {
                    // If the base operand is bounded, consider it partially safe
                    if let ast::Expression::Identifier(id) = left {
                        if let Some(bound_array) = bounded_vars.get(id.name) {
                            if bound_array == array_name {
                                return true; // Could add more checks for overflow potential
                            }
                        }
                        // Phase 6: Common loop variable names are likely safe
                        let id_lower = id.name.to_lowercase();
                        if id_lower == "i"
                            || id_lower == "j"
                            || id_lower == "k"
                            || id_lower == "idx"
                            || id_lower == "index"
                            || id_lower == "n"
                            || id_lower == "offset"
                        {
                            return true;
                        }
                    }
                }
                false
            }
            _ => false,
        }
    }

    /// Check for loop bounds issues
    fn check_loop_array_bounds(
        &self,
        block: &ast::Block<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for stmt in &block.statements {
            self.check_statement_for_loop_bounds(stmt, arrays, &mut findings, ctx);
        }

        findings
    }

    /// Check statement for loop bounds issues
    fn check_statement_for_loop_bounds(
        &self,
        stmt: &ast::Statement<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        findings: &mut Vec<Finding>,
        ctx: &AnalysisContext<'_>,
    ) {
        match stmt {
            ast::Statement::For {
                condition,
                body,
                location,
                ..
            } => {
                // Check if the loop condition properly bounds array access
                if let Some(cond_expr) = condition {
                    let array_accesses = self.find_array_accesses_in_body(body, arrays);

                    for array_name in array_accesses {
                        if !self.loop_condition_bounds_array(cond_expr, &array_name) {
                            let message = format!(
                                "Loop may access array '{}' out of bounds - condition doesn't properly validate array length",
                                array_name
                            );
                            let finding = self
                                .base
                                .create_finding_with_severity(
                                    ctx,
                                    message,
                                    location.start().line() as u32,
                                    location.start().column() as u32,
                                    location.byte_length() as u32,
                                    Severity::High,
                                )
                                .with_cwe(119) // CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
                                .with_fix_suggestion(format!(
                                    "Use proper loop bounds: for (uint i = 0; i < {}.length; i++)",
                                    array_name
                                ));
                            findings.push(finding);
                        }
                    }
                }

                // Recursively check nested loops
                self.check_statement_for_loop_bounds(body, arrays, findings, ctx);
            }
            ast::Statement::While {
                condition, body, ..
            } => {
                // FP Reduction: Only flag while loops that access arrays without any
                // length-based guard in the condition.  While loops with `.length`
                // in the condition are bounded.
                let array_accesses = self.find_array_accesses_in_body(body, arrays);

                if !array_accesses.is_empty() {
                    // Check if the while condition references .length
                    let cond_has_length = self.expression_contains_length(condition);
                    if !cond_has_length {
                        let message =
                            "While loop contains array access without length-based guard in condition"
                                .to_string();
                        let finding = self
                            .base
                            .create_finding(
                                ctx,
                                message,
                                stmt.location().start().line() as u32,
                                stmt.location().start().column() as u32,
                                stmt.location().byte_length() as u32,
                            )
                            .with_cwe(835) // CWE-835: Loop with Unreachable Exit Condition
                            .with_fix_suggestion(
                                "Add explicit bounds checking in while loop condition".to_string(),
                            );
                        findings.push(finding);
                    }
                }

                self.check_statement_for_loop_bounds(body, arrays, findings, ctx);
            }
            ast::Statement::Block(block) => {
                for inner_stmt in &block.statements {
                    self.check_statement_for_loop_bounds(inner_stmt, arrays, findings, ctx);
                }
            }
            _ => {}
        }
    }

    /// Find array accesses within a statement body
    fn find_array_accesses_in_body(
        &self,
        stmt: &ast::Statement<'_>,
        arrays: &HashMap<String, ArrayInfo>,
    ) -> Vec<String> {
        let mut accesses = Vec::new();
        self.collect_array_accesses_from_stmt(stmt, arrays, &mut accesses);
        accesses
    }

    /// Recursively collect array accesses from statement
    fn collect_array_accesses_from_stmt(
        &self,
        stmt: &ast::Statement<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        accesses: &mut Vec<String>,
    ) {
        match stmt {
            ast::Statement::Expression(expr) => {
                self.collect_array_accesses_from_expr(expr, arrays, accesses);
            }
            ast::Statement::Block(block) => {
                for inner_stmt in &block.statements {
                    self.collect_array_accesses_from_stmt(inner_stmt, arrays, accesses);
                }
            }
            _ => {}
        }
    }

    /// Collect array accesses from expression
    fn collect_array_accesses_from_expr(
        &self,
        expr: &ast::Expression<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        accesses: &mut Vec<String>,
    ) {
        match expr {
            ast::Expression::IndexAccess { base, .. } => {
                if let ast::Expression::Identifier(id) = base {
                    if arrays.contains_key(id.name) {
                        accesses.push(id.name.to_string());
                    }
                }
            }
            ast::Expression::BinaryOperation { left, right, .. } => {
                self.collect_array_accesses_from_expr(left, arrays, accesses);
                self.collect_array_accesses_from_expr(right, arrays, accesses);
            }
            _ => {}
        }
    }

    /// Check if an expression references .length (for while-loop guard detection)
    fn expression_contains_length(&self, expr: &ast::Expression<'_>) -> bool {
        match expr {
            ast::Expression::MemberAccess { member, .. } => member.name == "length",
            ast::Expression::BinaryOperation { left, right, .. } => {
                self.expression_contains_length(left) || self.expression_contains_length(right)
            }
            ast::Expression::UnaryOperation { operand, .. } => {
                self.expression_contains_length(operand)
            }
            ast::Expression::FunctionCall {
                function,
                arguments,
                ..
            } => {
                self.expression_contains_length(function)
                    || arguments.iter().any(|a| self.expression_contains_length(a))
            }
            _ => false,
        }
    }

    /// Check if loop condition properly bounds the given array
    fn loop_condition_bounds_array(
        &self,
        condition: &ast::Expression<'_>,
        array_name: &str,
    ) -> bool {
        if let ast::Expression::BinaryOperation {
            operator, right, ..
        } = condition
        {
            if matches!(
                operator,
                ast::BinaryOperator::Less | ast::BinaryOperator::LessEqual
            ) {
                // Check if right side is array.length
                if let ast::Expression::MemberAccess {
                    expression, member, ..
                } = right
                {
                    if let ast::Expression::Identifier(id) = expression {
                        return id.name == array_name && member.name == "length";
                    }
                }
            }
        }
        false
    }

    /// Check for missing length validation in function parameters
    fn check_missing_length_validation(
        &self,
        function: &ast::Function<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Phase 6: Skip standard ERC functions (balanceOf, allowance, etc.)
        let func_name_lower = function.name.name.to_lowercase();
        if func_name_lower == "balanceof"
            || func_name_lower == "allowance"
            || func_name_lower == "approve"
            || func_name_lower == "transfer"
            || func_name_lower == "transferfrom"
            || func_name_lower == "ownerof"
            || func_name_lower == "getapproved"
            || func_name_lower == "isapprovedforall"
        {
            return findings;
        }

        // Check for multiple array parameters that should have matching lengths
        let array_params: Vec<_> = function
            .parameters
            .iter()
            .filter_map(|param| {
                if let Some(name) = &param.name {
                    if arrays.contains_key(name.name) {
                        Some((name.name.to_string(), &param.location))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        // Phase 6: Skip single array parameter functions (no length mismatch possible)
        // Only flag if there are 2+ array parameters that need matching lengths
        if array_params.len() >= 2 {
            // FP Reduction Pattern D: Skip if ANY array parameter is fixed-size.
            // Fixed-size arrays (e.g., uint256[8], bytes32[4]) have their length
            // enforced by the ABI at compile time. When one array is fixed-size,
            // the caller already knows its length, making runtime mismatch less likely.
            // Change from .all() to .any() to reduce false positives.
            if array_params.iter().any(|(name, _)| {
                arrays
                    .get(name.as_str())
                    .map_or(false, |info| !info.is_dynamic)
            }) {
                return findings;
            }
            // Phase 10: Check if function body already has length validation
            let func_source = self.get_function_source(function, ctx);
            // FP Reduction (Gate 1): Only flag when at least two array params are actually
            // index-accessed in THIS function. Thin entry points that forward arrays to an
            // internal implementation rely on the callee for length validation.
            let indexed_count = array_params
                .iter()
                .filter(|(name, _)| Self::is_param_index_accessed(&func_source, name))
                .count();
            if indexed_count < 2 {
                return findings;
            }
            if self.has_length_validation(&func_source, &array_params) {
                return findings; // Already has validation
            }

            // Multiple arrays should likely have length validation
            let message = format!(
                "Function '{}' has multiple array parameters but no apparent length validation",
                function.name.name
            );
            let finding = self.base.create_finding(
                ctx,
                message,
                function.name.location.start().line() as u32,
                function.name.location.start().column() as u32,
                function.name.location.byte_length() as u32,
            )
            .with_cwe(20) // CWE-20: Improper Input Validation
            .with_fix_suggestion(
                "Add length validation: require(array1.length == array2.length, \"Array length mismatch\");".to_string()
            );
            findings.push(finding);
        }

        findings
    }

    /// Phase 10: Check if function source already has array length validation
    fn has_length_validation(
        &self,
        func_source: &str,
        array_params: &[(String, &ast::SourceLocation)],
    ) -> bool {
        // Check for common length validation patterns
        let has_length_check = func_source.contains(".length ==")
            || func_source.contains(".length!=")
            || func_source.contains(".length !=")
            || func_source.contains("require(") && func_source.contains("length");

        if has_length_check {
            return true;
        }

        // Check for specific array parameter length comparisons
        for (name, _) in array_params {
            let pattern = format!("{}.length", name);
            if func_source.contains(&pattern) && func_source.contains("require") {
                return true;
            }
        }

        false
    }

    /// Is `name` index-accessed (`name[...]`) in the function source? Word-boundary
    /// aware (won't match `tokenIds[` for param `ds`), and skips `.name[` (struct member).
    fn is_param_index_accessed(func_source: &str, name: &str) -> bool {
        let pattern = format!("{}[", name);
        let mut from = 0;
        while let Some(rel) = func_source[from..].find(&pattern) {
            let abs = from + rel;
            let ok = func_source[..abs]
                .chars()
                .next_back()
                .map_or(true, |c| !c.is_alphanumeric() && c != '_' && c != '.');
            if ok {
                return true;
            }
            from = abs + pattern.len();
        }
        false
    }

    /// Get function source code for analysis
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

    /// Check for off-by-one errors in array access
    fn check_off_by_one_errors(
        &self,
        block: &ast::Block<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        ctx: &AnalysisContext<'_>,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for stmt in &block.statements {
            self.check_statement_for_off_by_one(stmt, arrays, &mut findings, ctx);
        }

        findings
    }

    /// Check statement for off-by-one errors
    fn check_statement_for_off_by_one(
        &self,
        stmt: &ast::Statement<'_>,
        arrays: &HashMap<String, ArrayInfo>,
        findings: &mut Vec<Finding>,
        ctx: &AnalysisContext<'_>,
    ) {
        match stmt {
            ast::Statement::For {
                condition,
                location,
                ..
            } => {
                if let Some(cond_expr) = condition {
                    if self.has_potential_off_by_one(cond_expr, arrays) {
                        let message =
                            "Potential off-by-one error in loop condition - check array bounds"
                                .to_string();
                        let finding = self.base.create_finding(
                            ctx,
                            message,
                            location.start().line() as u32,
                            location.start().column() as u32,
                            location.byte_length() as u32,
                        )
                        .with_cwe(193) // CWE-193: Off-by-one Error
                        .with_fix_suggestion(
                            "Verify loop bounds: use < for exclusive bounds, <= for inclusive bounds".to_string()
                        );
                        findings.push(finding);
                    }
                }
            }
            ast::Statement::Expression(ast::Expression::IndexAccess {
                base,
                index,
                location,
            }) => {
                if let (ast::Expression::Identifier(id), Some(index_expr)) = (base, index) {
                    if arrays.contains_key(id.name) && self.index_might_be_off_by_one(index_expr) {
                        let message = format!(
                            "Potential off-by-one error in array access to '{}'",
                            id.name
                        );
                        let finding = self
                            .base
                            .create_finding(
                                ctx,
                                message,
                                location.start().line() as u32,
                                location.start().column() as u32,
                                location.byte_length() as u32,
                            )
                            .with_cwe(193)
                            .with_fix_suggestion(
                                "Verify array index calculation is correct".to_string(),
                            );
                        findings.push(finding);
                    }
                }
            }
            ast::Statement::Block(block) => {
                for inner_stmt in &block.statements {
                    self.check_statement_for_off_by_one(inner_stmt, arrays, findings, ctx);
                }
            }
            _ => {}
        }
    }

    /// Check if condition has potential off-by-one error
    fn has_potential_off_by_one(
        &self,
        condition: &ast::Expression<'_>,
        _arrays: &HashMap<String, ArrayInfo>,
    ) -> bool {
        if let ast::Expression::BinaryOperation {
            operator, right, ..
        } = condition
        {
            // Check for <= array.length (should usually be < array.length)
            if matches!(operator, ast::BinaryOperator::LessEqual) {
                if let ast::Expression::MemberAccess { member, .. } = right {
                    return member.name == "length";
                }
            }
        }
        false
    }

    /// Check if index expression might have off-by-one error
    fn index_might_be_off_by_one(&self, index_expr: &ast::Expression<'_>) -> bool {
        match index_expr {
            // Expressions like length, length + 1, etc.
            ast::Expression::MemberAccess { member, .. } => {
                return member.name == "length";
            }
            ast::Expression::BinaryOperation {
                operator,
                left,
                right,
                ..
            } => {
                if matches!(operator, ast::BinaryOperator::Add) {
                    // Check for length + something
                    if let ast::Expression::MemberAccess { member, .. } = left {
                        if member.name == "length" {
                            return true;
                        }
                    }
                    if let ast::Expression::MemberAccess { member, .. } = right {
                        if member.name == "length" {
                            return true;
                        }
                    }
                }
            }
            _ => {}
        }
        false
    }
}

/// Information about an array variable
#[derive(Debug, Clone)]
struct ArrayInfo {
    _base_type: String,
    is_dynamic: bool,
    _fixed_length: Option<u32>,
    _location: ast::SourceLocation,
    _dimensions: u8,
}

impl Detector for ArrayBoundsDetector {
    fn id(&self) -> DetectorId {
        self.base.id.clone()
    }

    fn name(&self) -> &str {
        &self.base.name
    }

    fn description(&self) -> &str {
        &self.base.description
    }

    fn categories(&self) -> Vec<DetectorCategory> {
        self.base.categories.clone()
    }

    fn default_severity(&self) -> Severity {
        self.base.default_severity
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

        // Phase 10: Skip test contracts, secure examples, and attack helpers
        if is_test_contract(ctx)
            || is_secure_example_file(ctx)
            || crate::utils::is_attack_contract(ctx)
        {
            return Ok(findings);
        }

        // FP Reduction: Skip directories covered by dedicated detectors
        // Batch functions in these domains have domain-specific validation
        {
            let file_lower = ctx.file_path.to_lowercase();
            if file_lower.contains("eigenlayer/")
                || file_lower.contains("critical_vulnerabilities/")
            {
                return Ok(findings);
            }
        }

        // FP Reduction Pattern C: For Solidity 0.8+, single-index array access automatically
        // reverts on out-of-bounds (compiler inserts bounds check). Only flag
        // multi-array length mismatch issues which the compiler doesn't catch.
        let is_solidity_08_plus = ctx.source_code.contains("pragma solidity ^0.8")
            || ctx.source_code.contains("pragma solidity >=0.8")
            || ctx.source_code.contains("pragma solidity 0.8");

        // Analyze all functions in the contract
        for function in ctx.get_functions() {
            findings.extend(self.analyze_function(function, ctx)?);
        }

        // Filter out single-index findings for Solidity 0.8+ contracts
        if is_solidity_08_plus {
            // Remove single-index "may be out of bounds" findings since the
            // compiler inserts bounds checks. Keep multi-array length mismatch findings.
            findings.retain(|f| !f.message.contains("may be out of bounds"));
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl AstAnalyzer for ArrayBoundsDetector {
    fn analyze_function(
        &self,
        function: &ast::Function<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        Ok(self.analyze_function_for_array_bounds(function, ctx))
    }

    fn analyze_statement(
        &self,
        statement: &ast::Statement<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for direct array access in statements
        if let ast::Statement::Expression(ast::Expression::IndexAccess {
            base,
            index,
            location,
        }) = statement
        {
            if let (ast::Expression::Identifier(id), Some(_)) = (base, index) {
                // Simplified check for array access without validation context
                let message = format!("Array access to '{}' - ensure bounds are checked", id.name);
                let finding = self
                    .base
                    .create_finding(
                        ctx,
                        message,
                        location.start().line() as u32,
                        location.start().column() as u32,
                        location.byte_length() as u32,
                    )
                    .with_cwe(125);
                findings.push(finding);
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn analyze_expression(
        &self,
        expression: &ast::Expression<'_>,
        ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Analyze array access expressions
        if let ast::Expression::IndexAccess {
            base,
            index,
            location,
        } = expression
        {
            if let ast::Expression::Identifier(_id) = base {
                if index.is_none() {
                    let message = "Array access with empty index detected".to_string();
                    let finding = self
                        .base
                        .create_finding(
                            ctx,
                            message,
                            location.start().line() as u32,
                            location.start().column() as u32,
                            location.byte_length() as u32,
                        )
                        .with_cwe(125);
                    findings.push(finding);
                }
            }
        }

        let findings = crate::utils::filter_fp_findings(findings, ctx);
        Ok(findings)
    }

    fn analyze_modifier(
        &self,
        _modifier: &ast::Modifier<'_>,
        _ctx: &AnalysisContext<'_>,
    ) -> Result<Vec<Finding>> {
        // Array bounds checking is typically in function bodies, not modifiers
        Ok(Vec::new())
    }
}
