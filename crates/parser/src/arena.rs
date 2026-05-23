use crate::error::{ParseError, ParseErrors, ParseResult};
use ast::{
    AssignmentOperator, AstArena, BinaryOperator, Block, Contract, ContractType, ElementaryType,
    Expression, Function, Identifier, Parameter, Position, SourceFile, SourceLocation,
    StateMutability, StateVariable, Statement, StorageLocation, TypeName, UnaryOperator,
    Visibility,
};
use solang_parser::{diagnostics, parse, pt};

/// Arena-based parser for converting solang AST to our arena-allocated AST
pub struct ArenaParser<'arena> {
    arena: &'arena AstArena,
}

impl<'arena> ArenaParser<'arena> {
    /// Default file ID used by solang-parser for single file parsing
    const DEFAULT_FILE_ID: usize = 0;

    /// Create a new arena parser
    pub fn new(arena: &'arena AstArena) -> Self {
        Self { arena }
    }

    /// Parse Solidity source code into arena-allocated AST
    pub fn parse(&self, source: &str, file_path: &str) -> Result<SourceFile<'arena>, ParseErrors> {
        // Parse using solang-parser
        let (parse_tree, _comments) = match parse(source, Self::DEFAULT_FILE_ID) {
            Ok((tree, comments)) => (tree, comments),
            Err(errors) => {
                let mut parse_errors = ParseErrors::new();
                for error in errors {
                    let location = self.convert_diagnostic_location(&error, file_path);
                    let parse_error = ParseError::syntax_error(format!("{:?}", error), location);
                    parse_errors.push(parse_error);
                }
                return Err(parse_errors);
            }
        };

        // Convert to our AST
        self.convert_source_unit(&parse_tree, source, file_path)
    }

    /// Convert solang source unit to our SourceFile
    fn convert_source_unit(
        &self,
        source_unit: &pt::SourceUnit,
        source: &str,
        file_path: &str,
    ) -> Result<SourceFile<'arena>, ParseErrors> {
        let path_str = self.arena.alloc_str(file_path);
        let content_str = self.arena.alloc_str(source);

        let location = SourceLocation::new(
            file_path.into(),
            Position::start(),
            Position::from_offset(source, source.len()),
        );

        let mut source_file = SourceFile::new(self.arena, path_str, content_str, location);
        let mut errors = ParseErrors::new();

        // Process each part of the source unit
        for part in &source_unit.0 {
            match self.convert_source_unit_part(part, source, file_path) {
                Ok(Some(contract)) => {
                    source_file.contracts.push(contract);
                }
                Ok(None) => {
                    // Non-contract part (pragma, import, etc.) - skip for now
                }
                Err(error) => {
                    errors.push(error);
                }
            }
        }

        if !errors.is_empty() {
            Err(errors)
        } else {
            Ok(source_file)
        }
    }

    /// Convert a source unit part
    fn convert_source_unit_part(
        &self,
        part: &pt::SourceUnitPart,
        source: &str,
        file_path: &str,
    ) -> ParseResult<Option<Contract<'arena>>> {
        match part {
            pt::SourceUnitPart::ContractDefinition(contract) => {
                let converted = self.convert_contract(contract, source, file_path)?;
                Ok(Some(converted))
            }
            pt::SourceUnitPart::PragmaDirective(_) => {
                // TODO: Convert pragma directives
                Ok(None)
            }
            pt::SourceUnitPart::ImportDirective(_) => {
                // TODO: Convert import directives
                Ok(None)
            }
            _ => {
                // Other parts (using for, error definitions, etc.)
                Ok(None)
            }
        }
    }

    /// Convert solang contract to our Contract
    fn convert_contract(
        &self,
        contract: &pt::ContractDefinition,
        source: &str,
        file_path: &str,
    ) -> ParseResult<Contract<'arena>> {
        let name = match &contract.name {
            Some(name) => self.convert_identifier_with_source(name, source, file_path)?,
            None => {
                let location =
                    self.convert_location_with_source(&contract.loc, file_path, Some(source));
                Identifier::new(self.arena.alloc_str(""), location)
            }
        };
        let contract_type = self.convert_contract_type(&contract.ty);
        let location = self.convert_location_with_source(&contract.loc, file_path, Some(source));

        let mut ast_contract = Contract::new(self.arena, name, contract_type, location);

        // Convert contract parts
        for part in &contract.parts {
            match part {
                pt::ContractPart::FunctionDefinition(func) => {
                    match self.convert_function(func, source, file_path) {
                        Ok(function) => ast_contract.functions.push(function),
                        Err(_) => {
                            // Skip invalid functions for now
                        }
                    }
                }
                pt::ContractPart::VariableDefinition(var) => {
                    match self.convert_state_variable(var, source, file_path) {
                        Ok(state_var) => ast_contract.state_variables.push(state_var),
                        Err(_) => {
                            // Skip invalid state variables for now
                        }
                    }
                }
                pt::ContractPart::EventDefinition(_event) => {
                    // TODO: Convert events
                }
                // pt::ContractPart::ModifierDefinition(modifier) => {
                //     // TODO: Convert modifiers
                // }
                _ => {
                    // Other parts
                }
            }
        }

        Ok(ast_contract)
    }

    /// Convert contract type
    fn convert_contract_type(&self, ty: &pt::ContractTy) -> ContractType {
        match ty {
            pt::ContractTy::Contract(_) => ContractType::Contract,
            pt::ContractTy::Interface(_) => ContractType::Interface,
            pt::ContractTy::Library(_) => ContractType::Library,
            pt::ContractTy::Abstract(_) => ContractType::Contract, // Treat abstract as contract
        }
    }

    /// Convert solang function to our Function
    fn convert_function(
        &self,
        func: &pt::FunctionDefinition,
        source: &str,
        file_path: &str,
    ) -> ParseResult<Function<'arena>> {
        let name = match &func.name {
            Some(name) => self.convert_identifier_with_source(name, source, file_path)?,
            None => {
                // Anonymous function (constructor, fallback, etc.)
                let location =
                    self.convert_location_with_source(&func.loc, file_path, Some(source));
                Identifier::new(self.arena.alloc_str(""), location)
            }
        };

        // CRITICAL FIX: Use complete function location including signature
        // func.loc_prototype contains the function signature (function name(...) modifiers)
        // func.loc contains the entire function including body
        // We need to span from the start of prototype to the end of the body
        let location = if matches!(func.loc_prototype, pt::Loc::File(..)) {
            // Create location spanning from prototype start to body end
            let proto_loc =
                self.convert_location_with_source(&func.loc_prototype, file_path, Some(source));
            let full_loc = self.convert_location_with_source(&func.loc, file_path, Some(source));
            ast::SourceLocation::new(file_path.into(), *proto_loc.start(), *full_loc.end())
        } else {
            // Fallback to full location if prototype location is not available
            self.convert_location_with_source(&func.loc, file_path, Some(source))
        };

        let mut function = Function::new(self.arena, name, location);

        // Convert function attributes (visibility, mutability, modifiers)
        for attr in &func.attributes {
            match attr {
                pt::FunctionAttribute::Visibility(vis) => {
                    function.visibility = self.convert_visibility(vis);
                }
                pt::FunctionAttribute::Mutability(mutability) => {
                    function.mutability = self.convert_mutability(mutability);
                }
                pt::FunctionAttribute::BaseOrModifier(loc, base) => {
                    // CRITICAL FIX: Populate modifiers field
                    if let Ok(modifier_invocation) =
                        self.convert_modifier_invocation(loc, base, source, file_path)
                    {
                        function.modifiers.push(modifier_invocation);
                    }
                }
                _ => {
                    // Ignore other attributes (Virtual, Immutable, Override, Error)
                }
            }
        }

        // Convert function parameters
        for param in &func.params {
            if let Ok(converted_param) = self.convert_parameter(param, source, file_path) {
                function.parameters.push(converted_param);
            }
        }

        // Convert return parameters
        for param in &func.returns {
            if let Ok(converted_param) = self.convert_parameter(param, source, file_path) {
                function.return_parameters.push(converted_param);
            }
        }

        // Convert function body
        if let Some(body_stmt) = &func.body {
            function.body = Some(self.convert_statement_to_block(body_stmt, source, file_path)?);
        }

        Ok(function)
    }

    /// Convert state variable
    fn convert_state_variable(
        &self,
        var: &pt::VariableDefinition,
        source: &str,
        file_path: &str,
    ) -> ParseResult<StateVariable<'arena>> {
        let name = if let Some(ref ident) = var.name {
            self.convert_identifier_with_source(ident, source, file_path)?
        } else {
            // Generate a placeholder name
            let location = self.convert_location_with_source(&var.loc, file_path, Some(source));
            Identifier::new(self.arena.alloc_str("_unnamed"), location)
        };
        let type_name = self.convert_type_name(&var.ty, source, file_path)?;
        let location = self.convert_location_with_source(&var.loc, file_path, Some(source));

        // Extract visibility from attributes
        let mut visibility = Visibility::Internal; // Default
        for attr in &var.attrs {
            if let pt::VariableAttribute::Visibility(vis) = attr {
                visibility = self.convert_visibility(vis);
            }
        }

        // TODO: Extract mutability and initial value
        let mutability = StateMutability::NonPayable; // Default for now
        let initial_value = None; // TODO: Convert var.initializer

        Ok(StateVariable {
            name,
            type_name,
            visibility,
            mutability,
            initial_value,
            location,
        })
    }

    /// Convert function parameter
    fn convert_parameter(
        &self,
        param: &(pt::Loc, Option<pt::Parameter>),
        source: &str,
        file_path: &str,
    ) -> ParseResult<Parameter<'arena>> {
        let (_loc, param_opt) = param;

        if let Some(pt_param) = param_opt {
            let name = if let Some(ref ident) = pt_param.name {
                Some(self.convert_identifier_with_source(ident, source, file_path)?)
            } else {
                None
            };

            let type_name = self.convert_type_name(&pt_param.ty, source, file_path)?;
            let storage_location = pt_param
                .storage
                .as_ref()
                .map(|s| self.convert_storage_location(s));
            let location =
                self.convert_location_with_source(&pt_param.loc, file_path, Some(source));

            Ok(Parameter {
                name,
                type_name,
                storage_location,
                location,
            })
        } else {
            Err(ParseError::SyntaxError {
                message: "Missing parameter definition".into(),
                location: self.convert_location_with_source(_loc, file_path, Some(source)),
            })
        }
    }

    /// Convert storage location
    fn convert_storage_location(&self, storage: &pt::StorageLocation) -> StorageLocation {
        match storage {
            pt::StorageLocation::Memory(_) => StorageLocation::Memory,
            pt::StorageLocation::Storage(_) => StorageLocation::Storage,
            pt::StorageLocation::Calldata(_) => StorageLocation::Calldata,
        }
    }

    /// Convert function visibility
    fn convert_visibility(&self, vis: &pt::Visibility) -> Visibility {
        match vis {
            pt::Visibility::Public(_) => Visibility::Public,
            pt::Visibility::Internal(_) => Visibility::Internal,
            pt::Visibility::External(_) => Visibility::External,
            pt::Visibility::Private(_) => Visibility::Private,
        }
    }

    /// Convert function mutability
    fn convert_mutability(&self, mutability: &pt::Mutability) -> StateMutability {
        match mutability {
            pt::Mutability::Pure(_) => StateMutability::Pure,
            pt::Mutability::View(_) => StateMutability::View,
            pt::Mutability::Constant(_) => StateMutability::View, // constant is deprecated, treat as view
            pt::Mutability::Payable(_) => StateMutability::Payable,
        }
    }

    /// Convert modifier invocation from solang Base to our ModifierInvocation
    fn convert_modifier_invocation(
        &self,
        loc: &pt::Loc,
        base: &pt::Base,
        source: &str,
        file_path: &str,
    ) -> ParseResult<ast::ModifierInvocation<'arena>> {
        // Base.name is an IdentifierPath, which is a list of identifiers
        // For modifiers, this is typically a single identifier (e.g., "onlyOwner")
        // For inheritance it can be a path (e.g., "A.B.C"), but we join them
        let name = if base.name.identifiers.is_empty() {
            // Shouldn't happen, but handle gracefully
            let location =
                self.convert_location_with_source(&base.name.loc, file_path, Some(source));
            Identifier::new(self.arena.alloc_str(""), location)
        } else if base.name.identifiers.len() == 1 {
            // Single identifier - typical case for modifiers
            self.convert_identifier_with_source(&base.name.identifiers[0], source, file_path)?
        } else {
            // Multiple identifiers - join them with "."
            let joined = base
                .name
                .identifiers
                .iter()
                .map(|id| id.name.as_str())
                .collect::<Vec<_>>()
                .join(".");
            let name_str = self.arena.alloc_str(&joined);
            let location =
                self.convert_location_with_source(&base.name.loc, file_path, Some(source));
            Identifier::new(name_str, location)
        };

        let location = self.convert_location_with_source(loc, file_path, Some(source));

        let mut arguments = bumpalo::collections::Vec::new_in(&self.arena.bump);

        // Convert modifier arguments if present
        if let Some(args) = &base.args {
            for arg in args {
                if let Ok(expr) = self.convert_expression(arg, source, file_path) {
                    arguments.push(expr);
                }
            }
        }

        Ok(ast::ModifierInvocation {
            name,
            arguments,
            location,
        })
    }

    /// Convert type name
    fn convert_type_name(
        &self,
        ty: &pt::Expression,
        source: &str,
        file_path: &str,
    ) -> ParseResult<TypeName<'arena>> {
        match ty {
            pt::Expression::Type(_, ty) => match ty {
                pt::Type::Address => Ok(TypeName::Elementary(ElementaryType::Address)),
                pt::Type::Bool => Ok(TypeName::Elementary(ElementaryType::Bool)),
                pt::Type::String => Ok(TypeName::Elementary(ElementaryType::String)),
                pt::Type::Bytes(n) => Ok(TypeName::Elementary(ElementaryType::FixedBytes(*n))),
                pt::Type::DynamicBytes => Ok(TypeName::Elementary(ElementaryType::Bytes)),
                pt::Type::Uint(n) => Ok(TypeName::Elementary(ElementaryType::Uint(*n))),
                pt::Type::Int(n) => Ok(TypeName::Elementary(ElementaryType::Int(*n))),
                pt::Type::Mapping { key, value, .. } => {
                    // Convert mapping type
                    let key_type = self
                        .arena
                        .alloc(self.convert_type_name(key, source, file_path)?);
                    let value_type = self
                        .arena
                        .alloc(self.convert_type_name(value, source, file_path)?);
                    Ok(TypeName::Mapping {
                        key_type,
                        value_type,
                    })
                }
                _ => {
                    // Fallback for unhandled types
                    Ok(TypeName::Elementary(ElementaryType::Uint(256)))
                }
            },
            pt::Expression::Variable(ident) => {
                // User-defined type
                let name = self.convert_identifier_with_source(ident, source, file_path)?;
                Ok(TypeName::UserDefined(name))
            }
            pt::Expression::ArraySubscript(_, base, length) => {
                // Check if this is a mapping (denoted by special syntax in the parser)
                // mappings look like: base[index] where if it's actually ArraySubscript
                // But when mapping(K => V), solang represents this differently
                // For now, treat as array
                let base_type = self
                    .arena
                    .alloc(self.convert_type_name(base, source, file_path)?);
                let length_expr = if let Some(len_expr) = length {
                    Some(
                        self.arena
                            .alloc(self.convert_expression(len_expr, source, file_path)?),
                    )
                } else {
                    None
                };
                Ok(TypeName::Array {
                    base_type,
                    length: length_expr,
                })
            }
            _ => {
                // Fallback for other types
                Ok(TypeName::Elementary(ElementaryType::Uint(256)))
            }
        }
    }

    /// Convert solang identifier to our Identifier
    #[allow(dead_code)]
    fn convert_identifier(
        &self,
        ident: &pt::Identifier,
        _source: &str,
        file_path: &str,
    ) -> ParseResult<Identifier<'arena>> {
        let name = self.arena.alloc_str(&ident.name);
        let location = self.convert_location(&ident.loc, file_path);
        Ok(Identifier::new(name, location))
    }

    /// Convert solang identifier to our Identifier with source for position calculation
    fn convert_identifier_with_source(
        &self,
        ident: &pt::Identifier,
        source: &str,
        file_path: &str,
    ) -> ParseResult<Identifier<'arena>> {
        let name = self.arena.alloc_str(&ident.name);
        let location = self.convert_location_with_source(&ident.loc, file_path, Some(source));
        Ok(Identifier::new(name, location))
    }

    /// Convert solang location to our SourceLocation
    #[allow(dead_code)]
    fn convert_location(&self, loc: &pt::Loc, file_path: &str) -> SourceLocation {
        self.convert_location_with_source(loc, file_path, None)
    }

    /// Convert solang location to our SourceLocation with optional source for position calculation
    fn convert_location_with_source(
        &self,
        loc: &pt::Loc,
        file_path: &str,
        source: Option<&str>,
    ) -> SourceLocation {
        match loc {
            pt::Loc::File(_file_no, start, end) => {
                // Calculate actual line/column positions from byte offsets if source is available
                let (start_pos, end_pos) = if let Some(src) = source {
                    let start_pos = Position::from_offset(src, *start);
                    let end_pos = Position::from_offset(src, *end);
                    (start_pos, end_pos)
                } else {
                    // Fallback to offset-only positions if source is not available
                    let start_pos = Position::new(1, 1, *start);
                    let end_pos = Position::new(1, 1, *end);
                    (start_pos, end_pos)
                };
                SourceLocation::new(file_path.into(), start_pos, end_pos)
            }
            pt::Loc::CommandLine => {
                SourceLocation::new(file_path.into(), Position::start(), Position::start())
            }
            pt::Loc::Builtin => {
                SourceLocation::new(file_path.into(), Position::start(), Position::start())
            }
            _ => SourceLocation::new(file_path.into(), Position::start(), Position::start()),
        }
    }

    /// Convert diagnostic location for error reporting
    fn convert_diagnostic_location(
        &self,
        _error: &diagnostics::Diagnostic,
        file_path: &str,
    ) -> SourceLocation {
        let start_pos = Position::new(1, 1, 0);
        let end_pos = Position::new(1, 1, 0);
        SourceLocation::new(file_path.into(), start_pos, end_pos)
    }

    /// Convert a solang statement to a Block (for function bodies)
    fn convert_statement_to_block(
        &self,
        stmt: &pt::Statement,
        source: &str,
        file_path: &str,
    ) -> ParseResult<Block<'arena>> {
        match stmt {
            pt::Statement::Block {
                loc, statements, ..
            } => {
                let location = self.convert_location_with_source(loc, file_path, Some(source));
                let mut block = Block::new(self.arena, location);

                for stmt in statements {
                    if let Ok(converted) = self.convert_statement(stmt, source, file_path) {
                        block.statements.push(converted);
                    }
                }

                Ok(block)
            }
            _ => {
                // For non-block statements, wrap in a block
                let location = self.convert_location_with_source(
                    &self.get_statement_location(stmt),
                    file_path,
                    Some(source),
                );
                let mut block = Block::new(self.arena, location);

                if let Ok(converted) = self.convert_statement(stmt, source, file_path) {
                    block.statements.push(converted);
                }

                Ok(block)
            }
        }
    }

    /// Convert a solang statement to our Statement
    fn convert_statement(
        &self,
        stmt: &pt::Statement,
        source: &str,
        file_path: &str,
    ) -> ParseResult<Statement<'arena>> {
        let location = self.convert_location_with_source(
            &self.get_statement_location(stmt),
            file_path,
            Some(source),
        );

        match stmt {
            pt::Statement::Block { statements, .. } => {
                let mut block = Block::new(self.arena, location);
                for stmt in statements {
                    if let Ok(converted) = self.convert_statement(stmt, source, file_path) {
                        block.statements.push(converted);
                    }
                }
                Ok(Statement::Block(block))
            }
            pt::Statement::Expression(_, expr) => {
                let converted_expr = self.convert_expression(expr, source, file_path)?;
                Ok(Statement::Expression(converted_expr))
            }
            pt::Statement::Return(_, expr_opt) => {
                let expr = if let Some(expr) = expr_opt {
                    Some(self.convert_expression(expr, source, file_path)?)
                } else {
                    None
                };
                Ok(Statement::Return {
                    value: expr,
                    location,
                })
            }
            pt::Statement::If(_, condition, then_stmt, else_stmt) => {
                let condition_expr = self.convert_expression(condition, source, file_path)?;
                let then_branch = self
                    .arena
                    .alloc(self.convert_statement(then_stmt, source, file_path)?);
                let else_branch = if let Some(else_stmt) = else_stmt {
                    Some(
                        self.arena
                            .alloc(self.convert_statement(else_stmt, source, file_path)?),
                    )
                } else {
                    None
                };
                Ok(Statement::If {
                    condition: condition_expr,
                    then_branch,
                    else_branch,
                    location,
                })
            }
            pt::Statement::While(_, condition, body) => {
                let condition_expr = self.convert_expression(condition, source, file_path)?;
                let body_stmt = self
                    .arena
                    .alloc(self.convert_statement(body, source, file_path)?);
                Ok(Statement::While {
                    condition: condition_expr,
                    body: body_stmt,
                    location,
                })
            }
            pt::Statement::DoWhile(_, body, condition) => {
                // Convert do-while statement
                let condition_expr = self.convert_expression(condition, source, file_path)?;
                let body_stmt = self
                    .arena
                    .alloc(self.convert_statement(body, source, file_path)?);

                // Create a while statement (our AST doesn't distinguish do-while from while)
                Ok(Statement::While {
                    condition: condition_expr,
                    body: body_stmt,
                    location,
                })
            }
            pt::Statement::Assembly { .. } => {
                // Convert assembly statement to a placeholder
                // Assembly blocks are unlikely to contain external calls relevant to reentrancy
                let dummy_expr = Expression::Literal {
                    value: ast::LiteralValue::String("assembly"),
                    location: location.clone(),
                };
                Ok(Statement::Expression(dummy_expr))
            }
            pt::Statement::For(_, init, condition, increment, body) => {
                let init_stmt = if let Some(init) = init {
                    Some(
                        self.arena
                            .alloc(self.convert_statement(init, source, file_path)?),
                    )
                } else {
                    None
                };
                let condition_expr = if let Some(condition) = condition {
                    Some(self.convert_expression(condition, source, file_path)?)
                } else {
                    None
                };
                let update_expr = if let Some(increment) = increment {
                    Some(self.convert_expression(increment, source, file_path)?)
                } else {
                    None
                };
                let body_stmt = if let Some(body) = body {
                    self.arena
                        .alloc(self.convert_statement(body, source, file_path)?)
                } else {
                    // Create empty block if no body
                    let dummy_block = Block::new(self.arena, location.clone());
                    self.arena.alloc(Statement::Block(dummy_block))
                };
                Ok(Statement::For {
                    init: init_stmt,
                    condition: condition_expr,
                    update: update_expr,
                    body: body_stmt,
                    location,
                })
            }
            pt::Statement::VariableDefinition(_, var_def, initial_value) => {
                // Convert variable declaration with optional initial value
                let mut declarations = bumpalo::collections::Vec::new_in(&self.arena.bump);

                // Convert the variable definition
                let var_name = if let Some(name) = &var_def.name {
                    self.convert_identifier_with_source(name, source, file_path)?
                } else {
                    // Create dummy identifier if name is None
                    ast::Identifier::new(
                        "_unnamed",
                        self.convert_location_with_source(&var_def.loc, file_path, Some(source)),
                    )
                };
                let var_location =
                    self.convert_location_with_source(&var_def.loc, file_path, Some(source));

                let var_decl = ast::VariableDeclaration {
                    name: var_name,
                    type_name: None, // TODO: Convert type if needed
                    storage_location: None,
                    location: var_location,
                };
                declarations.push(var_decl);

                // Convert initial value if present
                let initial_expr = if let Some(init_expr) = initial_value {
                    Some(self.convert_expression(init_expr, source, file_path)?)
                } else {
                    None
                };

                Ok(Statement::VariableDeclaration {
                    declarations,
                    initial_value: initial_expr,
                    location,
                })
            }
            pt::Statement::Try(_, expr, returns_and_stmt, catch_clauses) => {
                // Convert try-catch statement
                let try_expr = self.convert_expression(expr, source, file_path)?;

                // Extract try body from returns_and_stmt
                let try_body = if let Some((_, stmt)) = returns_and_stmt {
                    self.convert_statement_to_block(stmt, source, file_path)?
                } else {
                    // Create empty block if no try body
                    Block::new(self.arena, location.clone())
                };

                // Convert catch clauses
                let mut converted_catch_clauses =
                    bumpalo::collections::Vec::new_in(&self.arena.bump);
                for catch_clause in catch_clauses {
                    let (catch_location, catch_body) = match catch_clause {
                        pt::CatchClause::Simple(loc, _param, stmt) => {
                            let body = self.convert_statement_to_block(stmt, source, file_path)?;
                            (*loc, body)
                        }
                        pt::CatchClause::Named(loc, _ident, _param, stmt) => {
                            let body = self.convert_statement_to_block(stmt, source, file_path)?;
                            (*loc, body)
                        }
                    };

                    // Create a simple catch clause structure
                    let catch = ast::CatchClause {
                        identifier: None, // TODO: Convert identifier if needed
                        parameters: bumpalo::collections::Vec::new_in(&self.arena.bump),
                        body: catch_body,
                        location: self.convert_location_with_source(
                            &catch_location,
                            file_path,
                            Some(source),
                        ),
                    };
                    converted_catch_clauses.push(catch);
                }

                Ok(Statement::TryStatement {
                    expression: try_expr,
                    returns: None, // TODO: Implement proper returns conversion
                    body: try_body,
                    catch_clauses: converted_catch_clauses,
                    location,
                })
            }
            pt::Statement::Emit(_, expr) => {
                // Convert emit statement
                let event_expr = self.convert_expression(expr, source, file_path)?;
                Ok(Statement::EmitStatement {
                    event_call: event_expr,
                    location,
                })
            }
            pt::Statement::Revert(_, _, exprs) => {
                // Convert revert statement - just take first expression if any
                let error_expr = if let Some(expr) = exprs.first() {
                    Some(self.convert_expression(expr, source, file_path)?)
                } else {
                    None
                };
                Ok(Statement::RevertStatement {
                    error_call: error_expr,
                    location,
                })
            }
            _ => {
                // For unimplemented statement types, create a placeholder
                let dummy_expr = Expression::Literal {
                    value: ast::LiteralValue::Number("0"),
                    location: location.clone(),
                };
                Ok(Statement::Expression(dummy_expr))
            }
        }
    }

    /// Convert a solang expression to our Expression
    fn convert_expression(
        &self,
        expr: &pt::Expression,
        source: &str,
        file_path: &str,
    ) -> ParseResult<Expression<'arena>> {
        let location = self.convert_location_with_source(
            &self.get_expression_location(expr),
            file_path,
            Some(source),
        );

        match expr {
            pt::Expression::FunctionCall(_, function, args) => {
                // Handle regular function calls, including those where the function
                // might be a FunctionCallBlock (like call{value: amount}(""))
                let function_expr = self
                    .arena
                    .alloc(self.convert_expression(function, source, file_path)?);
                let mut arguments = bumpalo::collections::Vec::new_in(&self.arena.bump);

                // Convert the regular arguments
                for arg in args {
                    if let Ok(converted_arg) = self.convert_expression(arg, source, file_path) {
                        arguments.push(converted_arg);
                    }
                }

                let names = bumpalo::collections::Vec::new_in(&self.arena.bump);

                Ok(Expression::FunctionCall {
                    function: function_expr,
                    arguments,
                    names,
                    location,
                })
            }
            pt::Expression::FunctionCallBlock(_, function, block) => {
                // Handle function calls with blocks like msg.sender.call{value: amount}
                let function_expr = self
                    .arena
                    .alloc(self.convert_expression(function, source, file_path)?);
                let mut arguments = bumpalo::collections::Vec::new_in(&self.arena.bump);
                let names = bumpalo::collections::Vec::new_in(&self.arena.bump);

                // Parse the block to extract call options (like {value: amount, gas: 1000})
                // The block is a Statement::Block containing the options as expressions
                if let pt::Statement::Block { statements, .. } = block.as_ref() {
                    for stmt in statements {
                        // Each statement in the block should be an assignment-like expression
                        // representing call options like "value: amount" or "gas: 1000"
                        if let pt::Statement::Expression(_, expr) = stmt {
                            // Try to parse expressions in the block as call option assignments
                            if let Ok(arg_expr) = self.convert_expression(expr, source, file_path) {
                                arguments.push(arg_expr);
                            }
                        }
                    }
                }

                // Create FunctionCall that represents both the function and its call options
                // This maintains compatibility with the detector while preserving call option info
                Ok(Expression::FunctionCall {
                    function: function_expr,
                    arguments,
                    names,
                    location,
                })
            }
            pt::Expression::MemberAccess(_, expr, member) => {
                let expr_converted = self
                    .arena
                    .alloc(self.convert_expression(expr, source, file_path)?);
                let member_converted =
                    self.convert_identifier_with_source(member, source, file_path)?;

                Ok(Expression::MemberAccess {
                    expression: expr_converted,
                    member: member_converted,
                    location,
                })
            }
            pt::Expression::Variable(ident) => {
                let identifier = self.convert_identifier_with_source(ident, source, file_path)?;
                Ok(Expression::Identifier(identifier))
            }
            pt::Expression::Assign(_, left, right) => {
                let left_expr = self
                    .arena
                    .alloc(self.convert_expression(left, source, file_path)?);
                let right_expr = self
                    .arena
                    .alloc(self.convert_expression(right, source, file_path)?);

                Ok(Expression::Assignment {
                    left: left_expr,
                    operator: AssignmentOperator::Assign,
                    right: right_expr,
                    location,
                })
            }
            // Compound assignments: previously fell through to the placeholder
            // `Literal("0")` arm, which erased state-change semantics. Detectors
            // walking for `Expression::Assignment` (e.g. classic-reentrancy
            // checking for state writes after external calls) therefore missed
            // any function that uses `+=`, `-=`, etc. — including the canonical
            // CEI-violation pattern `balances[msg.sender] -= amount;`.
            pt::Expression::AssignAdd(_, left, right) => {
                let left_expr = self
                    .arena
                    .alloc(self.convert_expression(left, source, file_path)?);
                let right_expr = self
                    .arena
                    .alloc(self.convert_expression(right, source, file_path)?);
                Ok(Expression::Assignment {
                    left: left_expr,
                    operator: AssignmentOperator::AddAssign,
                    right: right_expr,
                    location,
                })
            }
            pt::Expression::AssignSubtract(_, left, right) => {
                let left_expr = self
                    .arena
                    .alloc(self.convert_expression(left, source, file_path)?);
                let right_expr = self
                    .arena
                    .alloc(self.convert_expression(right, source, file_path)?);
                Ok(Expression::Assignment {
                    left: left_expr,
                    operator: AssignmentOperator::SubAssign,
                    right: right_expr,
                    location,
                })
            }
            pt::Expression::AssignMultiply(_, left, right) => {
                let left_expr = self
                    .arena
                    .alloc(self.convert_expression(left, source, file_path)?);
                let right_expr = self
                    .arena
                    .alloc(self.convert_expression(right, source, file_path)?);
                Ok(Expression::Assignment {
                    left: left_expr,
                    operator: AssignmentOperator::MulAssign,
                    right: right_expr,
                    location,
                })
            }
            pt::Expression::AssignDivide(_, left, right) => {
                let left_expr = self
                    .arena
                    .alloc(self.convert_expression(left, source, file_path)?);
                let right_expr = self
                    .arena
                    .alloc(self.convert_expression(right, source, file_path)?);
                Ok(Expression::Assignment {
                    left: left_expr,
                    operator: AssignmentOperator::DivAssign,
                    right: right_expr,
                    location,
                })
            }
            pt::Expression::AssignModulo(_, left, right) => {
                let left_expr = self
                    .arena
                    .alloc(self.convert_expression(left, source, file_path)?);
                let right_expr = self
                    .arena
                    .alloc(self.convert_expression(right, source, file_path)?);
                Ok(Expression::Assignment {
                    left: left_expr,
                    operator: AssignmentOperator::ModAssign,
                    right: right_expr,
                    location,
                })
            }
            pt::Expression::AssignAnd(_, left, right) => {
                let left_expr = self
                    .arena
                    .alloc(self.convert_expression(left, source, file_path)?);
                let right_expr = self
                    .arena
                    .alloc(self.convert_expression(right, source, file_path)?);
                Ok(Expression::Assignment {
                    left: left_expr,
                    operator: AssignmentOperator::AndAssign,
                    right: right_expr,
                    location,
                })
            }
            pt::Expression::AssignOr(_, left, right) => {
                let left_expr = self
                    .arena
                    .alloc(self.convert_expression(left, source, file_path)?);
                let right_expr = self
                    .arena
                    .alloc(self.convert_expression(right, source, file_path)?);
                Ok(Expression::Assignment {
                    left: left_expr,
                    operator: AssignmentOperator::OrAssign,
                    right: right_expr,
                    location,
                })
            }
            pt::Expression::AssignXor(_, left, right) => {
                let left_expr = self
                    .arena
                    .alloc(self.convert_expression(left, source, file_path)?);
                let right_expr = self
                    .arena
                    .alloc(self.convert_expression(right, source, file_path)?);
                Ok(Expression::Assignment {
                    left: left_expr,
                    operator: AssignmentOperator::XorAssign,
                    right: right_expr,
                    location,
                })
            }
            pt::Expression::AssignShiftLeft(_, left, right) => {
                let left_expr = self
                    .arena
                    .alloc(self.convert_expression(left, source, file_path)?);
                let right_expr = self
                    .arena
                    .alloc(self.convert_expression(right, source, file_path)?);
                Ok(Expression::Assignment {
                    left: left_expr,
                    operator: AssignmentOperator::ShiftLeftAssign,
                    right: right_expr,
                    location,
                })
            }
            pt::Expression::AssignShiftRight(_, left, right) => {
                let left_expr = self
                    .arena
                    .alloc(self.convert_expression(left, source, file_path)?);
                let right_expr = self
                    .arena
                    .alloc(self.convert_expression(right, source, file_path)?);
                Ok(Expression::Assignment {
                    left: left_expr,
                    operator: AssignmentOperator::ShiftRightAssign,
                    right: right_expr,
                    location,
                })
            }
            pt::Expression::NamedFunctionCall(_, function, named_args) => {
                // Handle named function calls like function({name: value})
                let function_expr = self
                    .arena
                    .alloc(self.convert_expression(function, source, file_path)?);
                let mut arguments = bumpalo::collections::Vec::new_in(&self.arena.bump);
                let mut names = bumpalo::collections::Vec::new_in(&self.arena.bump);

                // Convert named arguments
                for named_arg in named_args {
                    if let Ok(arg_expr) =
                        self.convert_expression(&named_arg.expr, source, file_path)
                    {
                        arguments.push(arg_expr);
                        let name_ident = self.convert_identifier_with_source(
                            &named_arg.name,
                            source,
                            file_path,
                        )?;
                        names.push(name_ident);
                    }
                }

                Ok(Expression::FunctionCall {
                    function: function_expr,
                    arguments,
                    names,
                    location,
                })
            }
            pt::Expression::BoolLiteral(_, value) => Ok(Expression::Literal {
                value: ast::LiteralValue::Boolean(*value),
                location,
            }),
            pt::Expression::NumberLiteral(_, value, _exp, _unit) => {
                let number_str = self.arena.alloc_str(value);
                Ok(Expression::Literal {
                    value: ast::LiteralValue::Number(number_str),
                    location,
                })
            }
            pt::Expression::RationalNumberLiteral(_, value, _fraction, _exp, _unit) => {
                let number_str = self.arena.alloc_str(value);
                Ok(Expression::Literal {
                    value: ast::LiteralValue::Number(number_str),
                    location,
                })
            }
            pt::Expression::HexNumberLiteral(_, value, _) => {
                let hex_str = self.arena.alloc_str(value);
                Ok(Expression::Literal {
                    value: ast::LiteralValue::Number(hex_str),
                    location,
                })
            }
            pt::Expression::StringLiteral(string_lits) => {
                // Concatenate multiple string literals
                let combined = string_lits
                    .iter()
                    .map(|s| s.string.as_str())
                    .collect::<Vec<_>>()
                    .join("");
                let string_str = self.arena.alloc_str(&combined);
                Ok(Expression::Literal {
                    value: ast::LiteralValue::String(string_str),
                    location,
                })
            }
            pt::Expression::HexLiteral(hex_lits) => {
                // Concatenate multiple hex literals
                let combined = hex_lits
                    .iter()
                    .map(|h| h.hex.as_str())
                    .collect::<Vec<_>>()
                    .join("");
                let hex_str = self.arena.alloc_str(&combined);
                Ok(Expression::Literal {
                    value: ast::LiteralValue::HexString(hex_str),
                    location,
                })
            }
            pt::Expression::AddressLiteral(_, addr) => {
                let addr_str = self.arena.alloc_str(addr);
                Ok(Expression::Literal {
                    value: ast::LiteralValue::Address(addr_str),
                    location,
                })
            }
            // Binary operations
            pt::Expression::Add(_, left, right) => self.convert_binary_operation(
                left,
                right,
                BinaryOperator::Add,
                source,
                file_path,
                location,
            ),
            pt::Expression::Subtract(_, left, right) => self.convert_binary_operation(
                left,
                right,
                BinaryOperator::Sub,
                source,
                file_path,
                location,
            ),
            pt::Expression::Multiply(_, left, right) => self.convert_binary_operation(
                left,
                right,
                BinaryOperator::Mul,
                source,
                file_path,
                location,
            ),
            pt::Expression::Divide(_, left, right) => self.convert_binary_operation(
                left,
                right,
                BinaryOperator::Div,
                source,
                file_path,
                location,
            ),
            pt::Expression::Modulo(_, left, right) => self.convert_binary_operation(
                left,
                right,
                BinaryOperator::Mod,
                source,
                file_path,
                location,
            ),
            pt::Expression::Power(_, left, right) => self.convert_binary_operation(
                left,
                right,
                BinaryOperator::Pow,
                source,
                file_path,
                location,
            ),
            pt::Expression::Equal(_, left, right) => self.convert_binary_operation(
                left,
                right,
                BinaryOperator::Equal,
                source,
                file_path,
                location,
            ),
            pt::Expression::NotEqual(_, left, right) => self.convert_binary_operation(
                left,
                right,
                BinaryOperator::NotEqual,
                source,
                file_path,
                location,
            ),
            pt::Expression::Less(_, left, right) => self.convert_binary_operation(
                left,
                right,
                BinaryOperator::Less,
                source,
                file_path,
                location,
            ),
            pt::Expression::LessEqual(_, left, right) => self.convert_binary_operation(
                left,
                right,
                BinaryOperator::LessEqual,
                source,
                file_path,
                location,
            ),
            pt::Expression::More(_, left, right) => self.convert_binary_operation(
                left,
                right,
                BinaryOperator::Greater,
                source,
                file_path,
                location,
            ),
            pt::Expression::MoreEqual(_, left, right) => self.convert_binary_operation(
                left,
                right,
                BinaryOperator::GreaterEqual,
                source,
                file_path,
                location,
            ),
            pt::Expression::And(_, left, right) => self.convert_binary_operation(
                left,
                right,
                BinaryOperator::And,
                source,
                file_path,
                location,
            ),
            pt::Expression::Or(_, left, right) => self.convert_binary_operation(
                left,
                right,
                BinaryOperator::Or,
                source,
                file_path,
                location,
            ),
            pt::Expression::BitwiseAnd(_, left, right) => self.convert_binary_operation(
                left,
                right,
                BinaryOperator::BitwiseAnd,
                source,
                file_path,
                location,
            ),
            pt::Expression::BitwiseOr(_, left, right) => self.convert_binary_operation(
                left,
                right,
                BinaryOperator::BitwiseOr,
                source,
                file_path,
                location,
            ),
            pt::Expression::BitwiseXor(_, left, right) => self.convert_binary_operation(
                left,
                right,
                BinaryOperator::BitwiseXor,
                source,
                file_path,
                location,
            ),
            pt::Expression::ShiftLeft(_, left, right) => self.convert_binary_operation(
                left,
                right,
                BinaryOperator::ShiftLeft,
                source,
                file_path,
                location,
            ),
            pt::Expression::ShiftRight(_, left, right) => self.convert_binary_operation(
                left,
                right,
                BinaryOperator::ShiftRight,
                source,
                file_path,
                location,
            ),
            // Array access
            pt::Expression::ArraySubscript(_, array, index) => {
                let array_expr = self
                    .arena
                    .alloc(self.convert_expression(array, source, file_path)?);
                let index_expr = if let Some(idx) = index {
                    Some(
                        self.arena
                            .alloc(self.convert_expression(idx, source, file_path)?),
                    )
                } else {
                    None
                };

                Ok(Expression::IndexAccess {
                    base: array_expr,
                    index: index_expr,
                    location,
                })
            }
            // Unary operations
            pt::Expression::Not(_, expr) => {
                let operand = self
                    .arena
                    .alloc(self.convert_expression(expr, source, file_path)?);
                Ok(Expression::UnaryOperation {
                    operator: UnaryOperator::Not,
                    operand,
                    prefix: true,
                    location,
                })
            }
            pt::Expression::BitwiseNot(_, expr) => {
                let operand = self
                    .arena
                    .alloc(self.convert_expression(expr, source, file_path)?);
                Ok(Expression::UnaryOperation {
                    operator: UnaryOperator::BitwiseNot,
                    operand,
                    prefix: true,
                    location,
                })
            }
            pt::Expression::Negate(_, expr) => {
                let operand = self
                    .arena
                    .alloc(self.convert_expression(expr, source, file_path)?);
                Ok(Expression::UnaryOperation {
                    operator: UnaryOperator::Minus,
                    operand,
                    prefix: true,
                    location,
                })
            }
            pt::Expression::UnaryPlus(_, expr) => {
                let operand = self
                    .arena
                    .alloc(self.convert_expression(expr, source, file_path)?);
                Ok(Expression::UnaryOperation {
                    operator: UnaryOperator::Plus,
                    operand,
                    prefix: true,
                    location,
                })
            }
            _ => {
                // For unimplemented expression types, create a literal placeholder
                // TODO: Add proper logging here to debug what expression types are being missed
                Ok(Expression::Literal {
                    value: ast::LiteralValue::Number("0"),
                    location,
                })
            }
        }
    }

    /// Helper method to convert binary operations
    fn convert_binary_operation(
        &self,
        left: &pt::Expression,
        right: &pt::Expression,
        operator: BinaryOperator,
        source: &str,
        file_path: &str,
        location: SourceLocation,
    ) -> ParseResult<Expression<'arena>> {
        let left_expr = self
            .arena
            .alloc(self.convert_expression(left, source, file_path)?);
        let right_expr = self
            .arena
            .alloc(self.convert_expression(right, source, file_path)?);

        Ok(Expression::BinaryOperation {
            left: left_expr,
            operator,
            right: right_expr,
            location,
        })
    }

    /// Extract location from solang Statement
    fn get_statement_location(&self, stmt: &pt::Statement) -> pt::Loc {
        match stmt {
            pt::Statement::Block { loc, .. } => *loc,
            pt::Statement::Assembly { loc, .. } => *loc,
            pt::Statement::Args(loc, _) => *loc,
            pt::Statement::If(loc, ..) => *loc,
            pt::Statement::While(loc, ..) => *loc,
            pt::Statement::Expression(loc, _) => *loc,
            pt::Statement::VariableDefinition(loc, ..) => *loc,
            pt::Statement::For(loc, ..) => *loc,
            pt::Statement::DoWhile(loc, ..) => *loc,
            pt::Statement::Continue(loc) => *loc,
            pt::Statement::Break(loc) => *loc,
            pt::Statement::Return(loc, _) => *loc,
            pt::Statement::Revert(loc, ..) => *loc,
            pt::Statement::RevertNamedArgs(loc, ..) => *loc,
            pt::Statement::Emit(loc, _) => *loc,
            pt::Statement::Try(loc, ..) => *loc,
            pt::Statement::Error(loc) => *loc,
        }
    }

    /// Extract location from solang Expression
    fn get_expression_location(&self, expr: &pt::Expression) -> pt::Loc {
        match expr {
            pt::Expression::PostIncrement(loc, _) => *loc,
            pt::Expression::PostDecrement(loc, _) => *loc,
            pt::Expression::New(loc, _) => *loc,
            pt::Expression::ArraySubscript(loc, ..) => *loc,
            pt::Expression::ArraySlice(loc, ..) => *loc,
            pt::Expression::Parenthesis(loc, _) => *loc,
            pt::Expression::MemberAccess(loc, ..) => *loc,
            pt::Expression::FunctionCall(loc, ..) => *loc,
            pt::Expression::FunctionCallBlock(loc, ..) => *loc,
            pt::Expression::NamedFunctionCall(loc, ..) => *loc,
            pt::Expression::Not(loc, _) => *loc,
            pt::Expression::BitwiseNot(loc, _) => *loc,
            pt::Expression::Delete(loc, _) => *loc,
            pt::Expression::PreIncrement(loc, _) => *loc,
            pt::Expression::PreDecrement(loc, _) => *loc,
            pt::Expression::UnaryPlus(loc, _) => *loc,
            pt::Expression::Negate(loc, _) => *loc,
            pt::Expression::Power(loc, ..) => *loc,
            pt::Expression::Multiply(loc, ..) => *loc,
            pt::Expression::Divide(loc, ..) => *loc,
            pt::Expression::Modulo(loc, ..) => *loc,
            pt::Expression::Add(loc, ..) => *loc,
            pt::Expression::Subtract(loc, ..) => *loc,
            pt::Expression::ShiftLeft(loc, ..) => *loc,
            pt::Expression::ShiftRight(loc, ..) => *loc,
            pt::Expression::BitwiseAnd(loc, ..) => *loc,
            pt::Expression::BitwiseXor(loc, ..) => *loc,
            pt::Expression::BitwiseOr(loc, ..) => *loc,
            pt::Expression::Less(loc, ..) => *loc,
            pt::Expression::More(loc, ..) => *loc,
            pt::Expression::LessEqual(loc, ..) => *loc,
            pt::Expression::MoreEqual(loc, ..) => *loc,
            pt::Expression::Equal(loc, ..) => *loc,
            pt::Expression::NotEqual(loc, ..) => *loc,
            pt::Expression::And(loc, ..) => *loc,
            pt::Expression::Or(loc, ..) => *loc,
            pt::Expression::ConditionalOperator(loc, ..) => *loc,
            pt::Expression::Assign(loc, ..) => *loc,
            pt::Expression::AssignOr(loc, ..) => *loc,
            pt::Expression::AssignAnd(loc, ..) => *loc,
            pt::Expression::AssignXor(loc, ..) => *loc,
            pt::Expression::AssignShiftLeft(loc, ..) => *loc,
            pt::Expression::AssignShiftRight(loc, ..) => *loc,
            pt::Expression::AssignAdd(loc, ..) => *loc,
            pt::Expression::AssignSubtract(loc, ..) => *loc,
            pt::Expression::AssignMultiply(loc, ..) => *loc,
            pt::Expression::AssignDivide(loc, ..) => *loc,
            pt::Expression::AssignModulo(loc, ..) => *loc,
            pt::Expression::BoolLiteral(loc, _) => *loc,
            pt::Expression::NumberLiteral(loc, ..) => *loc,
            pt::Expression::RationalNumberLiteral(loc, ..) => *loc,
            pt::Expression::HexNumberLiteral(loc, ..) => *loc,
            pt::Expression::StringLiteral(string_lits) => {
                if let Some(first) = string_lits.first() {
                    first.loc
                } else {
                    pt::Loc::Builtin
                }
            }
            pt::Expression::Type(loc, _) => *loc,
            pt::Expression::HexLiteral(hex_lits) => {
                if let Some(first) = hex_lits.first() {
                    first.loc
                } else {
                    pt::Loc::Builtin
                }
            }
            pt::Expression::AddressLiteral(loc, _) => *loc,
            pt::Expression::Variable(ident) => ident.loc,
            pt::Expression::List(loc, _) => *loc,
            pt::Expression::ArrayLiteral(loc, _) => *loc,
        }
    }
}
