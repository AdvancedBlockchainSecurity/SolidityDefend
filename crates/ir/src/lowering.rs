use anyhow::{Result, anyhow};
use std::collections::HashMap;

use crate::instruction::*;
use ast::*;

/// Context for lowering AST to IR
pub struct LoweringContext {
    /// Current function being lowered
    current_function: Option<IrFunction>,
    /// Current basic block being populated
    current_block: Option<BlockId>,
    /// Variable mapping from AST identifiers to IR values
    variable_map: HashMap<String, ValueId>,
    /// Type mapping for variables
    type_map: HashMap<String, IrType>,
    /// Value counter for SSA form
    value_counter: u32,
    /// Block counter for CFG
    block_counter: u32,
    /// Break label stack for loops
    break_labels: Vec<BlockId>,
    /// Continue label stack for loops
    continue_labels: Vec<BlockId>,
}

impl Default for LoweringContext {
    fn default() -> Self {
        Self::new()
    }
}

impl LoweringContext {
    pub fn new() -> Self {
        Self {
            current_function: None,
            current_block: None,
            variable_map: HashMap::new(),
            type_map: HashMap::new(),
            value_counter: 0,
            block_counter: 0,
            break_labels: Vec::new(),
            continue_labels: Vec::new(),
        }
    }

    /// Create a new SSA value with the given type
    pub fn create_value(&mut self, ir_type: IrType) -> ValueId {
        let value_id = ValueId(self.value_counter);
        self.value_counter += 1;

        if let Some(ref mut function) = self.current_function {
            function.value_types.insert(value_id, ir_type);
        }

        value_id
    }

    /// Create a new basic block
    pub fn create_block(&mut self) -> BlockId {
        let block_id = BlockId(self.block_counter);
        self.block_counter += 1;

        if let Some(ref mut function) = self.current_function {
            function
                .basic_blocks
                .insert(block_id, BasicBlock::new(block_id));
        }

        block_id
    }

    /// Add an instruction to the current block
    pub fn add_instruction(&mut self, instruction: Instruction) -> Result<()> {
        if let (Some(ref mut function), Some(current_block)) =
            (&mut self.current_function, self.current_block)
        {
            function.add_instruction(current_block, instruction)
        } else {
            Err(anyhow!("No current function or block"))
        }
    }

    /// Switch to a different basic block
    pub fn set_current_block(&mut self, block_id: BlockId) {
        self.current_block = Some(block_id);
    }

    /// Register a variable in the current scope
    pub fn register_variable(&mut self, name: String, value_id: ValueId, ir_type: IrType) {
        self.variable_map.insert(name.clone(), value_id);
        self.type_map.insert(name, ir_type);
    }

    /// Look up a variable by name
    pub fn lookup_variable(&self, name: &str) -> Option<ValueId> {
        self.variable_map.get(name).copied()
    }

    /// Look up variable type by name
    pub fn lookup_variable_type(&self, name: &str) -> Option<&IrType> {
        self.type_map.get(name)
    }
}

/// Enhanced lowering implementation for AST to IR conversion
impl Lowering {
    /// Lower a complete source file to IR
    pub fn lower_source_file(&mut self, source_file: &SourceFile) -> Result<Vec<IrFunction>> {
        let mut ir_functions = Vec::new();

        for contract in &source_file.contracts {
            let contract_functions = self.lower_contract(contract)?;
            ir_functions.extend(contract_functions);
        }

        Ok(ir_functions)
    }

    /// Lower a contract to IR functions
    pub fn lower_contract(&mut self, contract: &Contract) -> Result<Vec<IrFunction>> {
        let mut ir_functions = Vec::new();

        for function in &contract.functions {
            let ir_function = self.lower_function_with_contract(function, contract)?;
            ir_functions.push(ir_function);
        }

        Ok(ir_functions)
    }

    /// Register Solidity global variables (msg, block, tx, etc.)
    fn register_global_variables(&mut self, context: &mut LoweringContext) {
        // msg global variable with address sender, uint256 value, bytes data, etc.
        let msg_type = IrType::Struct {
            name: "msg".to_string(),
            fields: vec![
                ("sender".to_string(), IrType::Address),
                ("value".to_string(), IrType::Uint(256)),
                ("data".to_string(), IrType::Bytes),
                ("sig".to_string(), IrType::FixedBytes(4)),
            ],
        };
        let msg_value = context.create_value(msg_type.clone());
        context.register_variable("msg".to_string(), msg_value, msg_type);

        // block global variable
        let block_type = IrType::Struct {
            name: "block".to_string(),
            fields: vec![
                ("number".to_string(), IrType::Uint(256)),
                ("timestamp".to_string(), IrType::Uint(256)),
                ("difficulty".to_string(), IrType::Uint(256)),
                ("gaslimit".to_string(), IrType::Uint(256)),
                ("coinbase".to_string(), IrType::Address),
            ],
        };
        let block_value = context.create_value(block_type.clone());
        context.register_variable("block".to_string(), block_value, block_type);

        // tx global variable
        let tx_type = IrType::Struct {
            name: "tx".to_string(),
            fields: vec![
                ("origin".to_string(), IrType::Address),
                ("gasprice".to_string(), IrType::Uint(256)),
            ],
        };
        let tx_value = context.create_value(tx_type.clone());
        context.register_variable("tx".to_string(), tx_value, tx_type);

        // this (contract address)
        let this_value = context.create_value(IrType::Address);
        context.register_variable("this".to_string(), this_value, IrType::Address);
    }

    /// Lower a single function with contract context (public API)
    pub fn lower_contract_function(
        &mut self,
        function: &Function,
        contract: &Contract,
    ) -> Result<IrFunction> {
        self.lower_function_with_contract(function, contract)
    }

    /// Lower a function with contract context
    fn lower_function_with_contract(
        &mut self,
        function: &Function,
        contract: &Contract,
    ) -> Result<IrFunction> {
        let mut context = LoweringContext::new();

        // Register Solidity global variables
        self.register_global_variables(&mut context);

        // Register state variables from the contract
        for state_var in &contract.state_variables {
            let var_name = state_var.name.name.to_string();
            if let Ok(ir_type) = self.lower_type_name(&state_var.type_name) {
                let value_id = context.create_value(ir_type.clone());
                context.register_variable(var_name.clone(), value_id, ir_type);
            }
        }

        // Convert AST parameter types to IR types
        let mut ir_parameters = Vec::new();
        for param in &function.parameters {
            let ir_type = self.lower_type_name(&param.type_name)?;
            let param_name = param
                .name
                .as_ref()
                .map(|id| id.name.to_string())
                .unwrap_or_else(|| format!("param_{}", ir_parameters.len()));
            ir_parameters.push((param_name, ir_type));
        }

        // Convert return parameter types
        let mut ir_return_types = Vec::new();
        for return_param in &function.return_parameters {
            let ir_type = self.lower_type_name(&return_param.type_name)?;
            ir_return_types.push(ir_type);
        }

        // Create IR function
        let ir_function = IrFunction::new(
            function.name.name.to_string(),
            ir_parameters,
            ir_return_types,
        );

        context.current_function = Some(ir_function.clone());
        context.current_block = Some(ir_function.entry_block);

        // Register function parameters as variables
        for (i, (param_name, param_type)) in ir_function.parameters.iter().enumerate() {
            let param_value = context.create_value(param_type.clone());
            context.register_variable(param_name.clone(), param_value, param_type.clone());

            // Add parameter assignment instruction
            context.add_instruction(Instruction::Assign(
                param_value,
                IrValue::Value(ValueId(i as u32)),
            ))?;
        }

        // Lower function body if present
        if let Some(body) = &function.body {
            self.lower_block(&mut context, body)?;
        }

        // Ensure function has a return instruction
        self.ensure_function_return(&mut context, &ir_function.return_types)?;

        // Update the function with the context state
        context
            .current_function
            .ok_or_else(|| anyhow!("Lost function context"))
    }

    /// Enhanced function lowering with complete implementation
    pub fn lower_function(&mut self, function: &Function) -> Result<IrFunction> {
        let mut context = LoweringContext::new();

        // Convert AST parameter types to IR types
        let mut ir_parameters = Vec::new();
        for param in &function.parameters {
            let ir_type = self.lower_type_name(&param.type_name)?;
            let param_name = param
                .name
                .as_ref()
                .map(|id| id.name.to_string())
                .unwrap_or_else(|| format!("param_{}", ir_parameters.len()));
            ir_parameters.push((param_name, ir_type));
        }

        // Convert return parameter types
        let mut ir_return_types = Vec::new();
        for return_param in &function.return_parameters {
            let ir_type = self.lower_type_name(&return_param.type_name)?;
            ir_return_types.push(ir_type);
        }

        // Create IR function
        let ir_function = IrFunction::new(
            function.name.name.to_string(),
            ir_parameters,
            ir_return_types,
        );

        context.current_function = Some(ir_function.clone());
        context.current_block = Some(ir_function.entry_block);

        // Register function parameters as variables
        for (i, (param_name, param_type)) in ir_function.parameters.iter().enumerate() {
            let param_value = context.create_value(param_type.clone());
            context.register_variable(param_name.clone(), param_value, param_type.clone());

            // Add parameter assignment instruction
            context.add_instruction(Instruction::Assign(
                param_value,
                IrValue::Value(ValueId(i as u32)),
            ))?;
        }

        // Lower function body if present
        if let Some(body) = &function.body {
            self.lower_block(&mut context, body)?;
        }

        // Ensure function has a return instruction
        self.ensure_function_return(&mut context, &ir_function.return_types)?;

        // Update the function with the context state
        context
            .current_function
            .ok_or_else(|| anyhow!("Lost function context"))
    }

    /// Lower a block statement
    fn lower_block(&mut self, context: &mut LoweringContext, block: &Block) -> Result<()> {
        for statement in &block.statements {
            self.lower_statement(context, statement)?;
        }
        Ok(())
    }

    /// Lower a statement to IR instructions
    fn lower_statement(
        &mut self,
        context: &mut LoweringContext,
        statement: &Statement,
    ) -> Result<()> {
        match statement {
            Statement::Block(block) => self.lower_block(context, block),

            Statement::Expression(expr) => {
                self.lower_expression(context, expr)?;
                Ok(())
            }

            Statement::VariableDeclaration {
                declarations,
                initial_value,
                ..
            } => {
                for declaration in declarations {
                    let var_name = declaration.name.name.to_string();

                    let ir_type = if let Some(type_name) = &declaration.type_name {
                        self.lower_type_name(type_name)?
                    } else {
                        // Infer type from initial value
                        if let Some(init_expr) = initial_value {
                            self.infer_expression_type(context, init_expr)?
                        } else {
                            return Err(anyhow!("Cannot infer type for variable {}", var_name));
                        }
                    };

                    let var_value = context.create_value(ir_type.clone());
                    context.register_variable(var_name, var_value, ir_type);

                    // Handle initial value
                    if let Some(init_expr) = initial_value {
                        let init_value = self.lower_expression(context, init_expr)?;
                        context.add_instruction(Instruction::Assign(var_value, init_value))?;
                    }
                }
                Ok(())
            }

            Statement::If {
                condition,
                then_branch,
                else_branch,
                ..
            } => {
                let cond_value = self.lower_expression(context, condition)?;

                let then_block = context.create_block();
                let else_block = if else_branch.is_some() {
                    context.create_block()
                } else {
                    context.create_block() // Merge block
                };
                let merge_block = context.create_block();

                // Add conditional branch
                context.add_instruction(Instruction::ConditionalBranch(
                    cond_value, then_block, else_block,
                ))?;

                // Lower then branch
                context.set_current_block(then_block);
                self.lower_statement(context, then_branch)?;
                if !self.is_terminator_statement(then_branch) {
                    context.add_instruction(Instruction::Branch(merge_block))?;
                }

                // Lower else branch if present
                context.set_current_block(else_block);
                if let Some(else_stmt) = else_branch {
                    self.lower_statement(context, else_stmt)?;
                    if !self.is_terminator_statement(else_stmt) {
                        context.add_instruction(Instruction::Branch(merge_block))?;
                    }
                } else {
                    context.add_instruction(Instruction::Branch(merge_block))?;
                }

                context.set_current_block(merge_block);
                Ok(())
            }

            Statement::While {
                condition, body, ..
            } => {
                let loop_header = context.create_block();
                let loop_body = context.create_block();
                let loop_exit = context.create_block();

                // Jump to loop header
                context.add_instruction(Instruction::Branch(loop_header))?;

                // Loop header: evaluate condition
                context.set_current_block(loop_header);
                let cond_value = self.lower_expression(context, condition)?;
                context.add_instruction(Instruction::ConditionalBranch(
                    cond_value, loop_body, loop_exit,
                ))?;

                // Loop body
                context.break_labels.push(loop_exit);
                context.continue_labels.push(loop_header);

                context.set_current_block(loop_body);
                self.lower_statement(context, body)?;
                if !self.is_terminator_statement(body) {
                    context.add_instruction(Instruction::Branch(loop_header))?;
                }

                context.break_labels.pop();
                context.continue_labels.pop();

                context.set_current_block(loop_exit);
                Ok(())
            }

            Statement::For {
                init,
                condition,
                update,
                body,
                ..
            } => {
                // Initialize
                if let Some(init_stmt) = init {
                    self.lower_statement(context, init_stmt)?;
                }

                let loop_header = context.create_block();
                let loop_body = context.create_block();
                let loop_update = context.create_block();
                let loop_exit = context.create_block();

                // Jump to loop header
                context.add_instruction(Instruction::Branch(loop_header))?;

                // Loop header: evaluate condition
                context.set_current_block(loop_header);
                if let Some(cond_expr) = condition {
                    let cond_value = self.lower_expression(context, cond_expr)?;
                    context.add_instruction(Instruction::ConditionalBranch(
                        cond_value, loop_body, loop_exit,
                    ))?;
                } else {
                    // Infinite loop
                    context.add_instruction(Instruction::Branch(loop_body))?;
                }

                // Loop body
                context.break_labels.push(loop_exit);
                context.continue_labels.push(loop_update);

                context.set_current_block(loop_body);
                self.lower_statement(context, body)?;
                if !self.is_terminator_statement(body) {
                    context.add_instruction(Instruction::Branch(loop_update))?;
                }

                // Loop update
                context.set_current_block(loop_update);
                if let Some(update_expr) = update {
                    self.lower_expression(context, update_expr)?;
                }
                context.add_instruction(Instruction::Branch(loop_header))?;

                context.break_labels.pop();
                context.continue_labels.pop();

                context.set_current_block(loop_exit);
                Ok(())
            }

            Statement::Return { value, .. } => {
                let return_value = if let Some(expr) = value {
                    Some(self.lower_expression(context, expr)?)
                } else {
                    None
                };
                context.add_instruction(Instruction::Return(return_value))?;
                Ok(())
            }

            Statement::Break { .. } => {
                if let Some(break_label) = context.break_labels.last() {
                    context.add_instruction(Instruction::Branch(*break_label))?;
                    Ok(())
                } else {
                    Err(anyhow!("Break statement outside of loop"))
                }
            }

            Statement::Continue { .. } => {
                if let Some(continue_label) = context.continue_labels.last() {
                    context.add_instruction(Instruction::Branch(*continue_label))?;
                    Ok(())
                } else {
                    Err(anyhow!("Continue statement outside of loop"))
                }
            }

            Statement::RevertStatement { error_call, .. } => {
                let error_value = if let Some(expr) = error_call {
                    Some(self.lower_expression(context, expr)?)
                } else {
                    None
                };
                context.add_instruction(Instruction::Revert(error_value))?;
                Ok(())
            }

            Statement::EmitStatement { event_call, .. } => {
                // Handle event emission
                if let Expression::FunctionCall {
                    function,
                    arguments,
                    ..
                } = event_call
                {
                    if let Expression::Identifier(event_name) = function {
                        let mut arg_values = Vec::new();
                        for arg in arguments {
                            arg_values.push(self.lower_expression(context, arg)?);
                        }
                        context.add_instruction(Instruction::EmitEvent(
                            event_name.name.to_string(),
                            arg_values,
                        ))?;
                    }
                }
                Ok(())
            }

            _ => {
                // For now, skip unsupported statements
                Ok(())
            }
        }
    }

    /// Lower an expression to an IR value
    fn lower_expression(
        &mut self,
        context: &mut LoweringContext,
        expression: &Expression,
    ) -> Result<IrValue> {
        match expression {
            Expression::Identifier(id) => {
                if let Some(value_id) = context.lookup_variable(id.name) {
                    Ok(IrValue::Value(value_id))
                } else {
                    Err(anyhow!("Undefined variable: {}", id.name))
                }
            }

            Expression::Literal { value, .. } => {
                match value {
                    LiteralValue::Boolean(b) => Ok(IrValue::ConstantBool(*b)),
                    LiteralValue::Number(n) => {
                        let num = n
                            .parse::<u64>()
                            .map_err(|_| anyhow!("Invalid number literal: {}", n))?;
                        Ok(IrValue::ConstantInt(num))
                    }
                    LiteralValue::String(s) => Ok(IrValue::ConstantString(s.to_string())),
                    LiteralValue::Address(addr) => {
                        // Parse hex address
                        let addr_bytes = hex::decode(&addr[2..]) // Remove 0x prefix
                            .map_err(|_| anyhow!("Invalid address literal: {}", addr))?;
                        if addr_bytes.len() != 20 {
                            return Err(anyhow!("Address must be 20 bytes"));
                        }
                        let mut address = [0u8; 20];
                        address.copy_from_slice(&addr_bytes);
                        Ok(IrValue::ConstantAddress(address))
                    }
                    LiteralValue::HexString(hex) => {
                        let bytes = hex::decode(&hex[2..]) // Remove 0x prefix
                            .map_err(|_| anyhow!("Invalid hex string: {}", hex))?;
                        Ok(IrValue::ConstantBytes(bytes))
                    }
                    _ => Ok(IrValue::ConstantString(format!("{:?}", value))),
                }
            }

            Expression::BinaryOperation {
                left,
                operator,
                right,
                ..
            } => {
                let left_val = self.lower_expression(context, left)?;
                let right_val = self.lower_expression(context, right)?;

                let result_type = self.infer_binary_result_type(left, right)?;
                let result_value = context.create_value(result_type);

                let instruction = match operator {
                    BinaryOperator::Add => Instruction::Add(result_value, left_val, right_val),
                    BinaryOperator::Sub => Instruction::Sub(result_value, left_val, right_val),
                    BinaryOperator::Mul => Instruction::Mul(result_value, left_val, right_val),
                    BinaryOperator::Div => Instruction::Div(result_value, left_val, right_val),
                    BinaryOperator::Mod => Instruction::Mod(result_value, left_val, right_val),
                    BinaryOperator::Pow => Instruction::Exp(result_value, left_val, right_val),
                    BinaryOperator::Equal => {
                        Instruction::Compare(result_value, CompareOp::Equal, left_val, right_val)
                    }
                    BinaryOperator::NotEqual => {
                        Instruction::Compare(result_value, CompareOp::NotEqual, left_val, right_val)
                    }
                    BinaryOperator::Less => {
                        Instruction::Compare(result_value, CompareOp::LessThan, left_val, right_val)
                    }
                    BinaryOperator::LessEqual => Instruction::Compare(
                        result_value,
                        CompareOp::LessEqual,
                        left_val,
                        right_val,
                    ),
                    BinaryOperator::Greater => Instruction::Compare(
                        result_value,
                        CompareOp::GreaterThan,
                        left_val,
                        right_val,
                    ),
                    BinaryOperator::GreaterEqual => Instruction::Compare(
                        result_value,
                        CompareOp::GreaterEqual,
                        left_val,
                        right_val,
                    ),
                    BinaryOperator::And => {
                        Instruction::LogicalAnd(result_value, left_val, right_val)
                    }
                    BinaryOperator::Or => Instruction::LogicalOr(result_value, left_val, right_val),
                    BinaryOperator::BitwiseAnd => {
                        Instruction::And(result_value, left_val, right_val)
                    }
                    BinaryOperator::BitwiseOr => Instruction::Or(result_value, left_val, right_val),
                    BinaryOperator::BitwiseXor => {
                        Instruction::Xor(result_value, left_val, right_val)
                    }
                    BinaryOperator::ShiftLeft => {
                        Instruction::Shl(result_value, left_val, right_val)
                    }
                    BinaryOperator::ShiftRight => {
                        Instruction::Shr(result_value, left_val, right_val)
                    }
                };

                context.add_instruction(instruction)?;
                Ok(IrValue::Value(result_value))
            }

            Expression::UnaryOperation {
                operator, operand, ..
            } => {
                let operand_val = self.lower_expression(context, operand)?;
                let result_type = self.infer_expression_type(context, operand)?;
                let result_value = context.create_value(result_type);

                let instruction = match operator {
                    UnaryOperator::Minus => {
                        // Implement as 0 - operand
                        Instruction::Sub(result_value, IrValue::ConstantInt(0), operand_val)
                    }
                    UnaryOperator::Not => Instruction::LogicalNot(result_value, operand_val),
                    UnaryOperator::BitwiseNot => Instruction::Not(result_value, operand_val),
                    _ => return Err(anyhow!("Unsupported unary operator: {:?}", operator)),
                };

                context.add_instruction(instruction)?;
                Ok(IrValue::Value(result_value))
            }

            Expression::Assignment {
                left,
                operator,
                right,
                ..
            } => {
                let right_val = self.lower_expression(context, right)?;

                // Handle different assignment types
                match operator {
                    AssignmentOperator::Assign => {
                        if let Expression::Identifier(id) = left {
                            if let Some(var_value) = context.lookup_variable(id.name) {
                                context.add_instruction(Instruction::Assign(
                                    var_value,
                                    right_val.clone(),
                                ))?;
                                Ok(right_val)
                            } else {
                                Err(anyhow!("Undefined variable in assignment: {}", id.name))
                            }
                        } else {
                            // Handle complex left-hand sides (array access, member access, etc.)
                            self.lower_complex_assignment(context, left, right_val.clone())?;
                            Ok(right_val)
                        }
                    }
                    _ => {
                        // Compound assignments: a += b becomes a = a + b
                        let left_val = self.lower_expression(context, left)?;
                        let result_type = self.infer_expression_type(context, left)?;
                        let result_value = context.create_value(result_type);

                        let op_instruction = match operator {
                            AssignmentOperator::AddAssign => {
                                Instruction::Add(result_value, left_val, right_val)
                            }
                            AssignmentOperator::SubAssign => {
                                Instruction::Sub(result_value, left_val, right_val)
                            }
                            AssignmentOperator::MulAssign => {
                                Instruction::Mul(result_value, left_val, right_val)
                            }
                            AssignmentOperator::DivAssign => {
                                Instruction::Div(result_value, left_val, right_val)
                            }
                            AssignmentOperator::ModAssign => {
                                Instruction::Mod(result_value, left_val, right_val)
                            }
                            _ => {
                                return Err(anyhow!(
                                    "Unsupported assignment operator: {:?}",
                                    operator
                                ));
                            }
                        };

                        context.add_instruction(op_instruction)?;

                        // Store result back to variable
                        if let Expression::Identifier(id) = left {
                            if let Some(var_value) = context.lookup_variable(id.name) {
                                context.add_instruction(Instruction::Assign(
                                    var_value,
                                    IrValue::Value(result_value),
                                ))?;
                            }
                        }

                        Ok(IrValue::Value(result_value))
                    }
                }
            }

            Expression::IndexAccess { base, index, .. } => {
                let base_val = self.lower_expression(context, base)?;
                if let Some(index_expr) = index {
                    let index_val = self.lower_expression(context, index_expr)?;
                    let result_type = self.infer_index_access_type(base)?;
                    let result_value = context.create_value(result_type);

                    // Determine if this is array or mapping access
                    let base_type = self.infer_expression_type(context, base)?;
                    let instruction = match base_type {
                        IrType::Array { .. } => {
                            Instruction::ArrayAccess(result_value, base_val, index_val)
                        }
                        IrType::Mapping { .. } => {
                            Instruction::MappingAccess(result_value, base_val, index_val)
                        }
                        _ => return Err(anyhow!("Index access on non-indexable type")),
                    };

                    context.add_instruction(instruction)?;
                    Ok(IrValue::Value(result_value))
                } else {
                    Err(anyhow!("Index access without index"))
                }
            }

            Expression::MemberAccess {
                expression, member, ..
            } => {
                let expr_val = self.lower_expression(context, expression)?;
                let result_type = self.infer_member_access_type(expression, member.name)?;
                let result_value = context.create_value(result_type);

                context.add_instruction(Instruction::StructAccess(
                    result_value,
                    expr_val,
                    member.name.to_string(),
                ))?;

                Ok(IrValue::Value(result_value))
            }

            Expression::FunctionCall {
                function,
                arguments,
                ..
            } => {
                let mut arg_values = Vec::new();
                for arg in arguments {
                    arg_values.push(self.lower_expression(context, arg)?);
                }

                // Peel call-option wrapper: `addr.call{value: x}(args)` parses as
                // FunctionCall(function: FunctionCall(MemberAccess), args), so the
                // outer FunctionCall's `function` is an inner FunctionCall whose
                // own `function` is the MemberAccess we care about. Without this
                // peel, low-level `.call{...}()` patterns silently fail to lower
                // to an ExternalCall instruction, and dataflow-based detectors
                // (e.g. classic-reentrancy) miss the canonical CEI-violation case.
                let resolved_target = match function {
                    Expression::FunctionCall {
                        function: inner_function,
                        ..
                    } => *inner_function,
                    _ => *function,
                };

                // Determine function name and type
                let (func_name, _is_external) = match resolved_target {
                    Expression::Identifier(id) => (id.name.to_string(), false),
                    Expression::MemberAccess {
                        expression, member, ..
                    } => {
                        // External call: contract.function()
                        let contract_val = self.lower_expression(context, expression)?;
                        let result_type = self.infer_function_call_type(resolved_target)?;
                        let result_value = context.create_value(result_type);

                        context.add_instruction(Instruction::ExternalCall(
                            result_value,
                            contract_val,
                            member.name.to_string(),
                            arg_values,
                        ))?;

                        return Ok(IrValue::Value(result_value));
                    }
                    _ => return Err(anyhow!("Unsupported function call expression")),
                };

                let result_type = self.infer_function_call_type(function)?;
                let result_value = context.create_value(result_type);

                context.add_instruction(Instruction::Call(result_value, func_name, arg_values))?;

                Ok(IrValue::Value(result_value))
            }

            _ => {
                // For unsupported expressions, return undefined
                Ok(IrValue::Undefined)
            }
        }
    }

    /// Lower a type name from AST to IR type
    fn lower_type_name(&self, type_name: &TypeName) -> Result<IrType> {
        match type_name {
            TypeName::Elementary(elem_type) => {
                Ok(match elem_type {
                    ElementaryType::Bool => IrType::Bool,
                    ElementaryType::String => IrType::String,
                    ElementaryType::Bytes => IrType::Bytes,
                    ElementaryType::FixedBytes(size) => IrType::FixedBytes(*size),
                    ElementaryType::Address => IrType::Address,
                    ElementaryType::Uint(bits) => IrType::Uint(*bits),
                    ElementaryType::Int(bits) => IrType::Int(*bits),
                    ElementaryType::Fixed(bits, _decimals) => {
                        // For now, treat as uint
                        IrType::Uint(*bits)
                    }
                    ElementaryType::Ufixed(bits, _decimals) => {
                        // For now, treat as uint
                        IrType::Uint(*bits)
                    }
                })
            }

            TypeName::UserDefined(id) => Ok(IrType::Contract(id.name.to_string())),

            TypeName::Array { base_type, length } => {
                let element_type = Box::new(self.lower_type_name(base_type)?);
                let array_length = if length.is_some() {
                    // For now, assume dynamic arrays
                    None
                } else {
                    None
                };
                Ok(IrType::Array {
                    element_type,
                    length: array_length,
                })
            }

            TypeName::Mapping {
                key_type,
                value_type,
            } => {
                let key_ir_type = Box::new(self.lower_type_name(key_type)?);
                let value_ir_type = Box::new(self.lower_type_name(value_type)?);
                Ok(IrType::Mapping {
                    key_type: key_ir_type,
                    value_type: value_ir_type,
                })
            }

            TypeName::Function {
                parameters,
                return_types,
                ..
            } => {
                let mut param_types = Vec::new();
                for param in parameters {
                    param_types.push(self.lower_type_name(param)?);
                }

                let mut ret_types = Vec::new();
                for ret_type in return_types {
                    ret_types.push(self.lower_type_name(ret_type)?);
                }

                Ok(IrType::Function {
                    parameters: param_types,
                    returns: ret_types,
                })
            }
        }
    }

    /// Helper methods for type inference and analysis
    fn infer_expression_type(
        &self,
        context: &LoweringContext,
        expr: &Expression,
    ) -> Result<IrType> {
        match expr {
            Expression::Identifier(id) => {
                // Look up variable type from context
                if let Some(ty) = context.lookup_variable_type(id.name) {
                    Ok(ty.clone())
                } else {
                    // Return default instead of error for now
                    Ok(IrType::Uint(256))
                }
            }
            Expression::Literal { value, .. } => {
                // Infer type from literal value
                match value {
                    ast::LiteralValue::Boolean(_) => Ok(IrType::Bool),
                    ast::LiteralValue::Number(_) => Ok(IrType::Uint(256)),
                    ast::LiteralValue::String(_) => Ok(IrType::String),
                    ast::LiteralValue::Address(_) => Ok(IrType::Address),
                    ast::LiteralValue::HexString(_) => Ok(IrType::Bytes),
                    _ => Ok(IrType::Uint(256)),
                }
            }
            Expression::MemberAccess {
                expression, member, ..
            } => {
                // Get the type of the base expression
                let base_type = self.infer_expression_type(context, expression)?;
                match base_type {
                    IrType::Struct { fields, .. } => {
                        // Look up field type
                        fields
                            .iter()
                            .find(|(name, _)| name == member.name)
                            .map(|(_, ty)| ty.clone())
                            .ok_or_else(|| anyhow!("Unknown field: {}", member.name))
                    }
                    _ => Ok(IrType::Uint(256)), // Simplified
                }
            }
            _ => Ok(IrType::Uint(256)), // Default fallback
        }
    }

    fn infer_binary_result_type(&self, _left: &Expression, _right: &Expression) -> Result<IrType> {
        // Simplified - return uint256 for most operations
        Ok(IrType::Uint(256))
    }

    fn infer_index_access_type(&self, _base: &Expression) -> Result<IrType> {
        // Simplified - return uint256
        Ok(IrType::Uint(256))
    }

    fn infer_member_access_type(&self, _expr: &Expression, _member: &str) -> Result<IrType> {
        // Simplified - return uint256
        Ok(IrType::Uint(256))
    }

    fn infer_function_call_type(&self, _func: &Expression) -> Result<IrType> {
        // Simplified - return uint256
        Ok(IrType::Uint(256))
    }

    fn lower_complex_assignment(
        &mut self,
        _context: &mut LoweringContext,
        _left: &Expression,
        _right_val: IrValue,
    ) -> Result<()> {
        // For now, simplified implementation
        Ok(())
    }

    fn is_terminator_statement(&self, statement: &Statement) -> bool {
        matches!(
            statement,
            Statement::Return { .. }
                | Statement::Break { .. }
                | Statement::Continue { .. }
                | Statement::RevertStatement { .. }
                | Statement::Throw { .. }
        )
    }

    fn ensure_function_return(
        &mut self,
        context: &mut LoweringContext,
        return_types: &[IrType],
    ) -> Result<()> {
        // Add implicit return if function doesn't end with terminator
        if return_types.is_empty() {
            context.add_instruction(Instruction::Return(None))?;
        } else {
            // For now, return undefined for non-void functions
            context.add_instruction(Instruction::Return(Some(IrValue::Undefined)))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lowering_context_creation() {
        let context = LoweringContext::new();
        assert!(context.current_function.is_none());
        assert!(context.current_block.is_none());
        assert_eq!(context.value_counter, 0);
        assert_eq!(context.block_counter, 0);
    }

    #[test]
    fn test_value_creation() {
        let mut context = LoweringContext::new();
        let value1 = context.create_value(IrType::Uint(256));
        let value2 = context.create_value(IrType::Bool);

        assert_eq!(value1, ValueId(0));
        assert_eq!(value2, ValueId(1));
        assert_eq!(context.value_counter, 2);
    }

    #[test]
    fn test_block_creation() {
        let mut context = LoweringContext::new();
        let block1 = context.create_block();
        let block2 = context.create_block();

        assert_eq!(block1, BlockId(0));
        assert_eq!(block2, BlockId(1));
        assert_eq!(context.block_counter, 2);
    }

    #[test]
    fn test_variable_registration() {
        let mut context = LoweringContext::new();
        let value_id = ValueId(42);
        let ir_type = IrType::Uint(256);

        context.register_variable("test_var".to_string(), value_id, ir_type.clone());

        assert_eq!(context.lookup_variable("test_var"), Some(value_id));
        assert_eq!(context.lookup_variable_type("test_var"), Some(&ir_type));
        assert_eq!(context.lookup_variable("nonexistent"), None);
    }

    #[test]
    fn test_type_lowering() {
        let lowering = Lowering::new();

        let uint256_type = TypeName::Elementary(ElementaryType::Uint(256));
        let ir_type = lowering.lower_type_name(&uint256_type).unwrap();
        assert_eq!(ir_type, IrType::Uint(256));

        let bool_type = TypeName::Elementary(ElementaryType::Bool);
        let ir_type = lowering.lower_type_name(&bool_type).unwrap();
        assert_eq!(ir_type, IrType::Bool);

        let address_type = TypeName::Elementary(ElementaryType::Address);
        let ir_type = lowering.lower_type_name(&address_type).unwrap();
        assert_eq!(ir_type, IrType::Address);
    }
}
