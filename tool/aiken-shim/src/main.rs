use aiken_project::{Project, options::Options, telemetry::EventListener};
use serde_json::{Value, json};
use std::{env, error::Error, io, path::PathBuf};
use uplc::ast::{Name, Program, Term as UplcTerm};

#[derive(Clone, Copy)]
struct Quiet;

impl EventListener for Quiet {}

fn failure(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

fn typed_ast(package: PathBuf) -> Result<Value, Box<dyn Error>> {
    let root = package.canonicalize()?;
    let mut project = Project::new(root.clone(), Quiet)?;
    project.compile(Options::default()).map_err(|errors| {
        failure(format!(
            "typed AST compilation failed with {} error(s)",
            errors.len()
        ))
    })?;

    let modules = project
        .modules()
        .into_iter()
        .filter(|module| {
            module.input_path.starts_with(&root)
                && !module.input_path.starts_with(root.join("build"))
        })
        .map(|module| {
            Ok(json!({
                "name": module.name,
                "path": module.input_path,
                "kind": format!("{:?}", module.kind),
                "package": module.package,
                "code": module.code,
                "ast": serde_json::to_value(module.ast.definitions)?,
            }))
        })
        .collect::<Result<Vec<Value>, serde_json::Error>>()?;

    Ok(json!({
        "backend": "aiken-lang",
        "compiler_revision": "8949565a9969278846ffefe30bc3b892029dd318",
        "modules": modules,
    }))
}

fn walk_builtins(term: &UplcTerm<Name>, path: &mut Vec<Value>, found: &mut Vec<Value>) {
    match term {
        UplcTerm::Var(_) | UplcTerm::Constant(_) | UplcTerm::Error => {}
        UplcTerm::Builtin(builtin) => found.push(json!({
            "uplc_name": builtin.to_string(),
            "path": path,
        })),
        UplcTerm::Delay(body) | UplcTerm::Force(body) => {
            path.push(json!("body"));
            walk_builtins(body, path, found);
            path.pop();
        }
        UplcTerm::Lambda { body, .. } => {
            path.push(json!("body"));
            walk_builtins(body, path, found);
            path.pop();
        }
        UplcTerm::Apply { function, argument } => {
            path.push(json!("function"));
            walk_builtins(function, path, found);
            path.pop();
            path.push(json!("argument"));
            walk_builtins(argument, path, found);
            path.pop();
        }
        UplcTerm::Constr { fields, .. } => {
            for (index, field) in fields.iter().enumerate() {
                path.push(json!("fields"));
                path.push(json!(index));
                walk_builtins(field, path, found);
                path.pop();
                path.pop();
            }
        }
        UplcTerm::Case { constr, branches } => {
            path.push(json!("constr"));
            walk_builtins(constr, path, found);
            path.pop();
            for (index, branch) in branches.iter().enumerate() {
                path.push(json!("branches"));
                path.push(json!(index));
                walk_builtins(branch, path, found);
                path.pop();
                path.pop();
            }
        }
    }
}
fn top_level_callable_arity(term: &UplcTerm<Name>) -> usize {
    match term {
        UplcTerm::Lambda { body, .. } => 1 + top_level_callable_arity(body),
        _ => 0,
    }
}


fn inspect_uplc(blueprint_path: PathBuf) -> Result<Value, Box<dyn Error>> {
    let blueprint = Project::<Quiet>::blueprint(&blueprint_path)?;
    let validators = blueprint
        .validators
        .iter()
        .map(|validator| {
            let program: Program<Name> = validator.program.inner().try_into().map_err(|error| {
                failure(format!("failed to decode {}: {error:?}", validator.title))
            })?;
            let mut builtins = Vec::new();
            walk_builtins(&program.term, &mut Vec::new(), &mut builtins);
            Ok(json!({
                "title": validator.title,
                "builtins": builtins,
                "top_level_callable_arity": top_level_callable_arity(&program.term),
                "abi_derivation_method": "decoded_uplc_top_level_lambda_spine",
                "abi_verifier_revision": "aiken-equiv-shim/v2",
                "program": program.to_pretty(),
            }))
        })
        .collect::<Result<Vec<Value>, io::Error>>()?;

    Ok(json!({
        "backend": "uplc",
        "compiler_revision": "8949565a9969278846ffefe30bc3b892029dd318",
        "validators": validators,
    }))
}

fn run() -> Result<String, Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let command = args
        .next()
        .ok_or_else(|| failure("expected typed-ast or inspect-uplc"))?;
    let path = PathBuf::from(args.next().ok_or_else(|| failure("expected a path"))?);
    if args.next().is_some() {
        return Err(failure("unexpected extra arguments").into());
    }

    let output = match command.as_str() {
        "typed-ast" => typed_ast(path)?,
        "inspect-uplc" => inspect_uplc(path)?,
        _ => return Err(failure(format!("unknown command: {command}")).into()),
    };
    Ok(serde_json::to_string(&output)?)
}

fn main() -> Result<(), Box<dyn Error>> {
    let worker = std::thread::Builder::new()
        .name("aiken-equiv-shim".to_string())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| run().map_err(|error| error.to_string()))?;
    let output = worker
        .join()
        .map_err(|_| failure("compiler shim worker panicked"))?
        .map_err(failure)?;
    println!("{output}");
    Ok(())
}
