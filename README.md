# Digital Transformation Compliance Auditor

## Project Overview

A compliance auditing assistant for digital transformation proposals. The tool reviews proposal text against a knowledge base of compliance requirements, retrieves evidence for the findings, and generates a structured compliance summary. The product is built with Python and Streamlit.

## Team
- Team name: Digital Transformation Compliance Auditor
- Members: [Add your names here]

## Problem Statement
Organizations often need to check whether digital transformation plans follow data privacy, access control, audit logging, and continuity requirements. Manual review is slow and inconsistent.

## Solution
The system uses a small retrieval-augmented generation pipeline (RAG) to ground answers in compliance guidelines, then applies an agent-style workflow with two tools: a compliance score calculator and a CSV report generator.

## Main Features
- Proposal text input and compliance review
- Retrieval-backed evidence from a knowledge base
- Structured output with gaps, recommendations, and score
- CSV export for compliance reports

## Architecture
- `app.py`: Streamlit interface
- `src/rag`: Knowledge ingestion and retrieval
- `src/agent`: Tool selection and orchestrator logic
- `src/llm`: OpenAI model calls and prompt construction
- `data/knowledge`: Compliance guideline source files

## Day 1 Concepts Used
- Model-to-solution flow in Python
- Prompt design with role, context, and structure
- Input validation and error handling
- Grounded output with evidence

## RAG Pipeline
- Knowledge files are loaded from `data/knowledge`
- Text is chunked and embedded
- Embeddings are stored locally as a JSON vector store
- User queries retrieve the top relevant evidence chunks

## Tools
1. `calculate_compliance_score` - computes a score based on identified compliance items
2. `generate_compliance_report` - creates a CSV report from the audit findings

## Local Setup
1. Create a Python environment
2. Install dependencies: `pip install -r requirements.txt`
3. Copy `.env.example` to `.env` and add `OPENAI_API_KEY`
4. Run the app: `streamlit run app.py`

## Environment Variables
- `OPENAI_API_KEY`
- `OPENAI_MODEL` (default `gpt-3.5-turbo`)
- `OPENAI_EMBEDDING_MODEL` (default `text-embedding-3-large`)
- `RAG_TOP_K` (default `4`)

## Data
- `data/knowledge/compliance_guidelines.txt` contains the sample compliance requirements used by the RAG pipeline.

## Limitations
- The current knowledge base is small and synthetic.
- The system depends on OpenAI API access for embeddings and generation.
- It does not yet support PDF ingestion or long document uploads.

## Future Improvements
- Add PDF and DOCX ingestion
- Use a proper vector database like Chroma, Qdrant or Supabase
- Add more compliance categories and company-specific rules
- Add a richer UI with file upload and interactive evidence selection
