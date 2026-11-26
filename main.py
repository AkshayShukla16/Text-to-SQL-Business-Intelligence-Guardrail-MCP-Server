import os
import json
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator

import aiomysql
import sqlglot
from sqlglot import exp
from dotenv import load_dotenv
from fastmcp import FastMCP, Context

load_dotenv()

MAX_ROW_LIMIT = 100
MAX_EXPLAIN_SCAN_ROWS = 50_000
PII_COLUMNS = {"email", "phone", "ssn", "password_hash", "credit_card"}


# ---------------------------------------------------------
# 1. LIFESPAN MANAGEMENT (Async Connection Pool)
# ---------------------------------------------------------
@dataclass
class AppContext:
    pool: aiomysql.Pool



@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Initializes a reusable async MySQL connection pool on startup and closes it on shutdown."""
    pool = await aiomysql.create_pool(
        host=os.getenv("MYSQL_HOST", "localhost"),
        port=int(os.getenv("MYSQL_PORT", 3306)),
        user=os.getenv("MYSQL_USER"),
        password=os.getenv("MYSQL_PASSWORD"),
        db=os.getenv("MYSQL_DATABASE"),
        minsize=2,
        maxsize=10,
        autocommit=True,
    )
    try:
        yield AppContext(pool=pool)
    finally:
        pool.close()
        await pool.wait_closed()


mcp = FastMCP("MySQL-BI-Guardrail-Enterprise", lifespan=app_lifespan)


# ---------------------------------------------------------
# 2. AST VALIDATION & AUTOMATIC LIMIT REWRITING
# ---------------------------------------------------------
def sanitize_and_rewrite_sql(sql: str) -> str:
    """
    Validates read-only safety via AST and enforces a maximum row LIMIT.
    """
    try:
        statements = sqlglot.parse(sql, read="mysql")
    except sqlglot.errors.ParseError as e:
        raise ValueError(f"SQL Parse Error: {str(e)}")

    if not statements or len(statements) > 1:
        raise ValueError("Only a single SQL statement is permitted.")

    stmt = statements[0]

    # Block anything other than SELECT (also handles UNIONs wrapped in Select/Union)
    if not isinstance(stmt, (exp.Select, exp.Union)):
        raise ValueError(f"Operation '{stmt.key.upper()}' is forbidden. Read-only access only.")

    # Deep AST walk to block hidden mutations or dangerous functions (e.g., SLEEP, BENCHMARK)
    forbidden_types = (
        exp.Insert, exp.Update, exp.Delete, exp.Drop,
        exp.Alter, exp.Create, exp.Command, exp.Transaction
    )
    for node in stmt.walk():
        if isinstance(node, forbidden_types):
            raise ValueError(f"Forbidden SQL construct detected: {node.key.upper()}")
        if isinstance(node, exp.Anonymous) and node.name.upper() in {"SLEEP", "BENCHMARK", "LOAD_FILE"}:
            raise ValueError(f"Forbidden MySQL function: {node.name.upper()}")

    # Automatically inject or cap LIMIT to prevent memory exhaustion
    existing_limit = stmt.args.get("limit")
    if existing_limit is None:
        stmt = stmt.limit(MAX_ROW_LIMIT)
    else:
        try:
            limit_val = int(existing_limit.expression.name)
            if limit_val > MAX_ROW_LIMIT:
                stmt = stmt.limit(MAX_ROW_LIMIT)
        except (ValueError, AttributeError):
            stmt = stmt.limit(MAX_ROW_LIMIT)

    return stmt.sql(dialect="mysql")


def mask_sensitive_rows(rows: list[dict]) -> list[dict]:
    """Redacts PII columns before sending query results back to the LLM."""
    masked_results = []
    for row in rows:
        clean_row = {}
        for col, val in row.items():
            if col.lower() in PII_COLUMNS and val is not None:
                clean_row[col] = "***REDACTED_PII***"
            else:
                clean_row[col] = val
        masked_results.append(clean_row)
    return masked_results


# ---------------------------------------------------------
# 3. GRANULAR MCP RESOURCES (Token-Efficient Schema Discovery)
# ---------------------------------------------------------
@mcp.resource("db://schemas/list")
async def get_table_names(ctx: Context) -> str:
    """Returns a lightweight list of available table names."""
    pool = ctx.request_context.lifespan_context.pool
    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SHOW TABLES;")
            tables = [row[0] for row in await cur.fetchall()]
            return json.dumps({"available_tables": tables})


@mcp.resource("db://schemas/{table_name}")
async def get_table_details(table_name: str, ctx: Context) -> str:
    """Returns exact DDL (CREATE TABLE) and 3 masked sample rows for a specific table."""
    # Validate table_name identifier safely using sqlglot
    safe_ident = exp.to_identifier(table_name).sql(dialect="mysql")
    pool = ctx.request_context.lifespan_context.pool

    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            # 1. Get DDL
            await cur.execute(f"SHOW CREATE TABLE {safe_ident};")
            ddl_row = await cur.fetchone()
            ddl = ddl_row.get("Create Table", "") if ddl_row else ""

            # 2. Get 3 sample rows (with PII masked)
            await cur.execute(f"SELECT * FROM {safe_ident} LIMIT 3;")
            samples = mask_sensitive_rows(await cur.fetchall())

            return json.dumps({"table": table_name, "ddl": ddl, "sample_rows": samples}, default=str, indent=2)


# ---------------------------------------------------------
# 4. OPTIMIZED MCP TOOLS (EXPLAIN + Safe Execution)
# ---------------------------------------------------------
@mcp.tool()
async def explain_query_plan(sql_query: str, ctx: Context) -> str:
    """
    Runs MySQL EXPLAIN on a query to inspect index usage and estimated row scans.
    Use this before running complex aggregations.
    """
    try:
        safe_sql = sanitize_and_rewrite_sql(sql_query)
    except ValueError as e:
        return f"❌ Validation Error: {str(e)}"

    pool = ctx.request_context.lifespan_context.pool
    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            await cur.execute(f"EXPLAIN {safe_sql}")
            plan = await cur.fetchall()
            return json.dumps(plan, default=str, indent=2)


@mcp.tool()
async def execute_readonly_sql(sql_query: str, ctx: Context) -> str:
    """
    Validates SQL AST, checks EXPLAIN cost to prevent full-table scans,
    executes the query, and masks PII columns.
    """
    try:
        safe_sql = sanitize_and_rewrite_sql(sql_query)
    except ValueError as e:
        return f"❌ Security Guardrail Blocked: {str(e)}"

    pool = ctx.request_context.lifespan_context.pool
    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            try:
                # Step A: Cost Guardrail via EXPLAIN
                await cur.execute(f"EXPLAIN {safe_sql}")
                plan_rows = await cur.fetchall()
                for step in plan_rows:
                    access_type = step.get("type")
                    est_rows = step.get("rows") or 0
                    if access_type == "ALL" and est_rows > MAX_EXPLAIN_SCAN_ROWS:
                        return (
                            f"⚠️ Performance Guardrail Blocked: Query triggers a full-table scan "
                            f"(~{est_rows} rows) on table '{step.get('table')}'. "
                            f"Add an indexed WHERE filter."
                        )

                # Step B: Execute Validated Query
                await cur.execute(safe_sql)
                raw_rows = await cur.fetchall()

                # Step C: Mask PII before returning to LLM
                clean_rows = mask_sensitive_rows(raw_rows)

                return json.dumps(
                    {
                        "executed_sql": safe_sql,
                        "row_count": len(clean_rows),
                        "data": clean_rows,
                    },
                    default=str,
                    indent=2,
                )
            except aiomysql.Error as err:
                return f"❌ Database Error: {str(err)}"


if __name__ == "__main__":
    # Remote Streamable HTTP server ready for cloud deployment or remote clients
    #mcp.run(transport="http", host="0.0.0.0", port=8000)
    mcp.run()