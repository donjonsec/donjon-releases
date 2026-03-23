#!/usr/bin/env python3
"""
Donjon Platform - AI Engine

Unified AI backend that auto-detects the best available provider:
  1. Local Ollama instance   (air-gapped friendly, full data stays local)
  2. Step 3.5 Flash          (via STEPFUN_API_KEY -- 196B MoE, 11B active, fast)
  3. Anthropic Claude API    (via ANTHROPIC_API_KEY env var)
  4. Google Gemini API       (via GEMINI_API_KEY env var -- fast & cheap)
  5. OpenAI-compatible API   (via OPENAI_API_KEY env var)
  6. Template fallback       (pure-Python, always available, no LLM needed)

All LLM-generated output is tagged for human review.
Only stdlib imports are used for HTTP calls (urllib).
"""

import json
import os
import logging
import ssl
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Internal imports (relative / absolute fallback pattern)
# ---------------------------------------------------------------------------
try:
    from .paths import paths
except ImportError:
    try:
        from paths import paths
    except ImportError:
        paths = None

try:
    from .ai_prompts import (
        SYSTEM_PROMPT,
        FINDING_ANALYSIS_PROMPT,
        TRIAGE_PROMPT,
        REMEDIATION_PROMPT,
        SCAN_SUMMARY_PROMPT,
        QUERY_PROMPT,
        MODELFILE_TEMPLATE,
    )
except ImportError:
    try:
        from ai_prompts import (
            SYSTEM_PROMPT,
            FINDING_ANALYSIS_PROMPT,
            TRIAGE_PROMPT,
            REMEDIATION_PROMPT,
            SCAN_SUMMARY_PROMPT,
            QUERY_PROMPT,
            MODELFILE_TEMPLATE,
        )
    except ImportError:
        # Minimal fallback if ai_prompts is missing entirely
        SYSTEM_PROMPT = "You are a cybersecurity analyst."
        FINDING_ANALYSIS_PROMPT = "Analyze this finding:\n{finding_json}"
        TRIAGE_PROMPT = "Prioritize these findings:\n{findings_json}"
        REMEDIATION_PROMPT = "Provide remediation for:\n{finding_json}"
        SCAN_SUMMARY_PROMPT = "Summarize this scan:\n{scan_data_json}"
        QUERY_PROMPT = "Question: {question}\nContext: {context_json}"
        MODELFILE_TEMPLATE = "FROM {base_model}\nSYSTEM \"You are a cybersecurity analyst.\""

try:
    from .logger import get_logger
except ImportError:
    try:
        from logger import get_logger
    except ImportError:
        get_logger = None

if get_logger is not None:
    logger = get_logger('ai_engine')
else:
    logger = logging.getLogger('ai_engine')
    if not logger.handlers:
        logger.addHandler(logging.StreamHandler())
        logger.setLevel(logging.INFO)


def _validate_url(url: str) -> str:
    """Validate URL uses allowed scheme (https only in production)."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme not in ('https', 'http'):  # http allowed for localhost dev
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme}")
    return url


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
AI_DISCLAIMER = "\n--- AI-Generated - Verify Before Acting ---\n"

OLLAMA_BASE_URL = os.environ.get('OLLAMA_URL', 'http://localhost:11434')
STEPFUN_API_URL = "https://api.stepfun.ai/v1/chat/completions"
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models"
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
# AWS Bedrock — region-specific endpoint, constructed at runtime
BEDROCK_API_TEMPLATE = "https://bedrock-runtime.{region}.amazonaws.com/model/{model}/invoke"

# OpenAI-compatible cloud providers — all use Bearer auth + chat/completions
_OPENAI_COMPAT_PROVIDERS = {
    'mistral': {
        'url': 'https://api.mistral.ai/v1/chat/completions',
        'env_key': 'MISTRAL_API_KEY',
        'default_model': 'mistral-large-latest',
        'label': 'Mistral AI',
    },
    'cohere': {
        'url': 'https://api.cohere.com/v2/chat',
        'env_key': 'COHERE_API_KEY',
        'default_model': 'command-r-plus',
        'label': 'Cohere',
    },
    'xai': {
        'url': 'https://api.x.ai/v1/chat/completions',
        'env_key': 'XAI_API_KEY',
        'default_model': 'grok-3',
        'label': 'xAI Grok',
    },
    'deepseek': {
        'url': 'https://api.deepseek.com/chat/completions',
        'env_key': 'DEEPSEEK_API_KEY',
        'default_model': 'deepseek-chat',
        'label': 'DeepSeek',
    },
    'together': {
        'url': 'https://api.together.xyz/v1/chat/completions',
        'env_key': 'TOGETHER_API_KEY',
        'default_model': 'meta-llama/Llama-3.3-70B-Instruct-Turbo',
        'label': 'Together AI',
    },
    'groq': {
        'url': 'https://api.groq.com/openai/v1/chat/completions',
        'env_key': 'GROQ_API_KEY',
        'default_model': 'llama-3.3-70b-versatile',
        'label': 'Groq',
    },
    'fireworks': {
        'url': 'https://api.fireworks.ai/inference/v1/chat/completions',
        'env_key': 'FIREWORKS_API_KEY',
        'default_model': 'accounts/fireworks/models/llama-v3p3-70b-instruct',
        'label': 'Fireworks AI',
    },
    'azure': {
        'url': '',  # Requires AZURE_OPENAI_ENDPOINT env var
        'env_key': 'AZURE_OPENAI_API_KEY',
        'default_model': 'gpt-4',
        'label': 'Azure OpenAI',
    },
    'openrouter': {
        'url': 'https://openrouter.ai/api/v1/chat/completions',
        'env_key': 'OPENROUTER_API_KEY',
        'default_model': 'anthropic/claude-sonnet-4',
        'label': 'OpenRouter (multi-model)',
    },
}

# Model preference order when scanning Ollama for available models
_OLLAMA_MODEL_PREFERENCE = [
    'qwen3-coder', 'qwen3.5', 'qwen2.5-coder',
    'step-3.5-flash', 'donjon-security',
    'llama3.2', 'llama3.1', 'llama3', 'mistral', 'codellama',
    'mixtral', 'phi3', 'gemma2', 'deepseek-coder', 'qwen2',
]

# Bedrock model IDs — mapped to friendly names for config
_BEDROCK_MODELS = {
    'claude-sonnet': 'anthropic.claude-sonnet-4-20250514-v1:0',
    'claude-haiku': 'anthropic.claude-haiku-4-5-20251001-v1:0',
    'claude-opus': 'anthropic.claude-opus-4-20250514-v1:0',
}

# Severity helpers for template fallback
_SEVERITY_ORDER = {'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1}
_SLA_MAP = {
    'CRITICAL': 'IMMEDIATE (24h)',
    'HIGH': 'URGENT (7d)',
    'MEDIUM': 'STANDARD (30d)',
    'LOW': 'PLANNED (90d)',
    'INFO': 'PLANNED (90d)',
}


class AIEngine:
    """
    Unified AI analysis engine for the Donjon Platform.

    Auto-detects the best available backend on initialisation and exposes
    high-level analysis methods.  Every method has a template fallback that
    produces structured output without any LLM, so the platform always
    functions even in fully air-gapped environments.
    """

    # Path to persisted AI configuration
    _CONFIG_PATH: Optional[Path] = None

    def __init__(self):
        self.backend: str = 'template'
        self.model_name: Optional[str] = None
        self._api_key: Optional[str] = None
        self._api_url: Optional[str] = None
        # AWS Bedrock fields
        self._aws_region: str = 'us-east-1'
        self._aws_access_key: Optional[str] = None
        self._aws_secret_key: Optional[str] = None
        self._aws_session_token: Optional[str] = None
        # Usage metering — tracks tokens for billing (especially Bedrock)
        self._usage_log: List[Dict] = []
        self._total_input_tokens: int = 0
        self._total_output_tokens: int = 0
        self._total_requests: int = 0

        # Resolve config path
        if paths:
            self._CONFIG_PATH = Path(paths.data) / 'ai_config.json'
        else:
            self._CONFIG_PATH = Path('data') / 'ai_config.json'

        # Try loading from config file first, then fall back to env detection
        if not self._load_config_file():
            self._detect_backend()

        logger.info(
            "AIEngine initialised: backend=%s, model=%s",
            self.backend, self.model_name,
        )

    # ------------------------------------------------------------------
    # Config file support
    # ------------------------------------------------------------------

    def _load_config_file(self) -> bool:
        """Load AI config from data/ai_config.json. Returns True if loaded."""
        try:
            if self._CONFIG_PATH and self._CONFIG_PATH.exists():
                with open(self._CONFIG_PATH, 'r', encoding='utf-8') as f:
                    cfg = json.load(f)
                backend = cfg.get('backend', '')
                if backend and backend != 'auto':
                    return self._apply_config(cfg)
        except Exception as exc:
            logger.debug("Could not load AI config file: %s", exc)
        return False

    def _apply_config(self, cfg: Dict) -> bool:
        """Apply a config dict to set backend/model/keys."""
        backend = cfg.get('backend', '')
        if not backend:
            return False

        if backend == 'ollama':
            self.backend = 'ollama'
            self._api_url = cfg.get('ollama_url', OLLAMA_BASE_URL)
            self.model_name = cfg.get('ollama_model') or cfg.get('model') or 'mistral'
            return True
        elif backend == 'anthropic':
            self.backend = 'anthropic'
            self._api_key = cfg.get('api_key', '')
            self.model_name = cfg.get('api_model') or cfg.get('model') or 'claude-sonnet-4-20250514'
            return True
        elif backend == 'openai':
            self.backend = 'openai'
            self._api_key = cfg.get('api_key', '')
            self._api_url = cfg.get('api_url', OPENAI_API_URL)
            self.model_name = cfg.get('api_model') or cfg.get('model') or 'gpt-4'
            return True
        elif backend == 'stepfun':
            self.backend = 'stepfun'
            self._api_key = cfg.get('api_key', '')
            self.model_name = cfg.get('api_model') or cfg.get('model') or 'step-3.5-flash'
            return True
        elif backend == 'gemini':
            self.backend = 'gemini'
            self._api_key = cfg.get('api_key', '')
            self.model_name = cfg.get('api_model') or cfg.get('model') or 'gemini-2.5-flash'
            return True
        elif backend in _OPENAI_COMPAT_PROVIDERS:
            provider = _OPENAI_COMPAT_PROVIDERS[backend]
            self.backend = 'openai'
            self._api_key = cfg.get('api_key', '') or os.environ.get(provider['env_key'], '')
            self._api_url = cfg.get('api_url', '') or provider['url']
            self.model_name = cfg.get('model', '') or provider['default_model']
            if backend == 'azure':
                base = cfg.get('azure_endpoint', '') or os.environ.get('AZURE_OPENAI_ENDPOINT', '')
                deployment = cfg.get('model', '') or os.environ.get('AZURE_OPENAI_DEPLOYMENT', 'gpt-4')
                self._api_url = f"{base}/openai/deployments/{deployment}/chat/completions?api-version=2024-02-01"
                self.model_name = deployment
            return True
        elif backend == 'bedrock':
            self.backend = 'bedrock'
            self._aws_region = cfg.get('aws_region', 'us-east-1')
            self._aws_access_key = cfg.get('aws_access_key_id') or os.environ.get('AWS_ACCESS_KEY_ID')
            self._aws_secret_key = cfg.get('aws_secret_access_key') or os.environ.get('AWS_SECRET_ACCESS_KEY')
            self._aws_session_token = cfg.get('aws_session_token') or os.environ.get('AWS_SESSION_TOKEN')
            model_alias = cfg.get('model', 'claude-sonnet')
            self.model_name = _BEDROCK_MODELS.get(model_alias, model_alias)
            return True
        elif backend == 'custom':
            self.backend = 'openai'  # custom uses OpenAI-compatible format
            self._api_key = cfg.get('api_key', '')
            self._api_url = cfg.get('api_url', '')
            self.model_name = cfg.get('api_model') or cfg.get('model') or 'default'
            return True
        return False

    def reconfigure(self, config: Dict) -> None:
        """Hot-reload AI settings from a config dict and save to disk."""
        self._apply_config(config)
        # Persist to file
        try:
            if self._CONFIG_PATH:
                self._CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
                with open(self._CONFIG_PATH, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=2)
        except Exception as exc:
            logger.warning("Could not save AI config: %s", exc)
        logger.info(
            "AIEngine reconfigured: backend=%s, model=%s",
            self.backend, self.model_name,
        )

    def test_connection(self) -> Dict:
        """Send a test prompt and return success/failure."""
        try:
            response = self._call_ai("Respond with exactly: MODEL_OK")
            ok = 'MODEL_OK' in (response or '')
            return {
                'success': ok,
                'backend': self.backend,
                'model': self.model_name,
                'response': response[:200] if response else '',
            }
        except Exception as exc:
            return {
                'success': False,
                'backend': self.backend,
                'model': self.model_name,
                'error': str(exc),
            }

    @staticmethod
    def get_supported_backends() -> List[Dict]:
        """Return list of all supported AI backends with their config requirements."""
        backends = [
            {'id': 'ollama', 'label': 'Ollama (Local)', 'requires': 'OLLAMA_URL or localhost:11434',
             'airgap': True, 'metered': False},
            {'id': 'bedrock', 'label': 'AWS Bedrock', 'requires': 'AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY',
             'airgap': False, 'metered': True, 'billing_note': 'Per-token billing via AWS'},
            {'id': 'anthropic', 'label': 'Anthropic Claude (Direct)', 'requires': 'ANTHROPIC_API_KEY',
             'airgap': False, 'metered': True},
            {'id': 'openai', 'label': 'OpenAI', 'requires': 'OPENAI_API_KEY',
             'airgap': False, 'metered': True},
            {'id': 'gemini', 'label': 'Google Gemini', 'requires': 'GEMINI_API_KEY',
             'airgap': False, 'metered': True},
            {'id': 'stepfun', 'label': 'StepFun Step 3.5 Flash', 'requires': 'STEPFUN_API_KEY',
             'airgap': False, 'metered': True},
        ]
        for pid, pinfo in _OPENAI_COMPAT_PROVIDERS.items():
            if pid not in ('azure',):  # Azure is special
                backends.append({
                    'id': pid, 'label': pinfo['label'],
                    'requires': pinfo['env_key'],
                    'default_model': pinfo['default_model'],
                    'airgap': False, 'metered': True,
                })
        backends.append({
            'id': 'azure', 'label': 'Azure OpenAI',
            'requires': 'AZURE_OPENAI_API_KEY + AZURE_OPENAI_ENDPOINT',
            'airgap': False, 'metered': True,
        })
        backends.append({
            'id': 'template', 'label': 'Template Fallback (No LLM)',
            'requires': 'Nothing', 'airgap': True, 'metered': False,
        })
        return backends

    def get_config(self) -> Dict:
        """Return current config (with masked API keys)."""
        config: Dict[str, Any] = {
            'backend': self.backend,
            'model': self.model_name,
            'available': self.backend != 'template',
        }
        # Load raw config from file if available
        try:
            if self._CONFIG_PATH and self._CONFIG_PATH.exists():
                with open(self._CONFIG_PATH, 'r', encoding='utf-8') as f:
                    raw = json.load(f)
                config.update(raw)
                # Mask API key
                if config.get('api_key') and len(config['api_key']) > 8:
                    config['api_key'] = '****...' + config['api_key'][-4:]
        except Exception:
            pass
        return config

    # ------------------------------------------------------------------
    # Backend detection
    # ------------------------------------------------------------------

    def _detect_backend(self) -> None:
        """
        Probe available AI backends in priority order.

        1. Local Ollama instance (best for air-gapped / privacy).
        2. Anthropic Claude API  (ANTHROPIC_API_KEY).
        3. OpenAI-compatible API (OPENAI_API_KEY).
        4. Template fallback     (always available).
        """
        # 1. Ollama
        try:
            req = urllib.request.Request(
                f"{OLLAMA_BASE_URL}/api/tags",
                headers={'User-Agent': 'Donjon/1.0'},
                method='GET',
            )
            with urllib.request.urlopen(req, timeout=3) as resp:  # nosec B310 -- URL constructed from hardcoded OLLAMA_BASE_URL constant
                data = json.loads(resp.read().decode('utf-8'))
                models = [m.get('name', '') for m in data.get('models', [])]
                if models:
                    self.backend = 'ollama'
                    self.model_name = self._pick_best_ollama_model(models)
                    return
        except Exception:
            pass

        # 2. AWS Bedrock (for managed environments)
        if os.environ.get('AWS_ACCESS_KEY_ID') and os.environ.get('DONJON_AI_BACKEND') == 'bedrock':
            self.backend = 'bedrock'
            self._aws_region = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
            self._aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
            self._aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
            self._aws_session_token = os.environ.get('AWS_SESSION_TOKEN')
            self.model_name = _BEDROCK_MODELS.get('claude-sonnet', 'anthropic.claude-sonnet-4-20250514-v1:0')
            return

        # 3. StepFun Step 3.5 Flash (196B MoE, 11B active, fast agentic model)
        if os.environ.get('STEPFUN_API_KEY'):
            self.backend = 'stepfun'
            self.model_name = 'step-3.5-flash'
            return

        # 3. Anthropic
        if os.environ.get('ANTHROPIC_API_KEY'):
            self.backend = 'anthropic'
            self.model_name = 'claude-sonnet-4-20250514'
            return

        # 4. Google Gemini (fast, cheap, generous free tier)
        if os.environ.get('GEMINI_API_KEY'):
            self.backend = 'gemini'
            self.model_name = 'gemini-2.5-flash'
            return

        # 5. OpenAI
        if os.environ.get('OPENAI_API_KEY'):
            self.backend = 'openai'
            self.model_name = 'gpt-4'
            return

        # 7. Any OpenAI-compatible cloud provider (check env keys)
        for provider_id, provider_info in _OPENAI_COMPAT_PROVIDERS.items():
            env_key = provider_info['env_key']
            if os.environ.get(env_key):
                self.backend = 'openai'  # All use OpenAI-compatible format
                self._api_key = os.environ[env_key]
                self._api_url = provider_info['url']
                self.model_name = provider_info['default_model']
                # Azure needs endpoint from env
                if provider_id == 'azure':
                    base = os.environ.get('AZURE_OPENAI_ENDPOINT', '')
                    deployment = os.environ.get('AZURE_OPENAI_DEPLOYMENT', 'gpt-4')
                    self._api_url = f"{base}/openai/deployments/{deployment}/chat/completions?api-version=2024-02-01"
                    self.model_name = deployment
                logger.info("Detected %s via %s", provider_info['label'], env_key)
                return

        # 8. Fallback
        self.backend = 'template'
        self.model_name = None

    @staticmethod
    def _pick_best_ollama_model(available: List[str]) -> str:
        """Choose the best Ollama model from the available list."""
        # Strip tag suffixes for matching (e.g. "llama3:latest" -> "llama3")
        normalised = {m.split(':')[0].lower(): m for m in available}
        for preferred in _OLLAMA_MODEL_PREFERENCE:
            if preferred in normalised:
                return normalised[preferred]
        # Fall back to whatever is first
        return available[0] if available else 'mistral'

    # ------------------------------------------------------------------
    # Low-level backend calls
    # ------------------------------------------------------------------

    def _call_ollama(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """POST to the local Ollama /api/generate endpoint (streaming)."""
        base = self._api_url or OLLAMA_BASE_URL
        url = _validate_url(f"{base}/api/generate")
        payload = {
            'model': self.model_name,
            'prompt': prompt,
            'stream': True,
            'options': {
                'temperature': 0.3,
                'num_predict': 2048,
            },
        }
        if system_prompt:
            payload['system'] = system_prompt

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'Donjon/1.0',
            },
            method='POST',
        )

        chunks: List[str] = []
        final_obj = {}
        with urllib.request.urlopen(req, timeout=180) as resp:
            for line in resp:
                if not line:
                    continue
                try:
                    obj = json.loads(line.decode('utf-8'))
                    token = obj.get('response', '')
                    if token:
                        chunks.append(token)
                    if obj.get('done', False):
                        final_obj = obj
                        break
                except json.JSONDecodeError:
                    continue

        # Ollama returns token counts in the final 'done' message
        if final_obj:
            self._record_usage(
                input_tokens=final_obj.get('prompt_eval_count', 0),
                output_tokens=final_obj.get('eval_count', 0),
                model=self.model_name or 'ollama',
            )

        return ''.join(chunks).strip()

    def _call_anthropic(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """POST to the Anthropic Messages API using stdlib urllib."""
        api_key = self._api_key or os.environ.get('ANTHROPIC_API_KEY', '')
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable is not set")

        payload = {
            'model': self.model_name or 'claude-sonnet-4-20250514',
            'max_tokens': 2048,
            'messages': [
                {'role': 'user', 'content': prompt},
            ],
        }
        if system_prompt:
            payload['system'] = system_prompt

        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            ANTHROPIC_API_URL,
            data=json.dumps(payload).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'x-api-key': api_key,
                'anthropic-version': '2023-06-01',
                'User-Agent': 'Donjon/1.0',
            },
            method='POST',
        )

        with urllib.request.urlopen(req, timeout=90, context=ctx) as resp:  # nosec B310 -- URL is hardcoded ANTHROPIC_API_URL constant
            result = json.loads(resp.read().decode('utf-8'))

        # Track usage for billing
        usage = result.get('usage', {})
        self._record_usage(
            input_tokens=usage.get('input_tokens', 0),
            output_tokens=usage.get('output_tokens', 0),
            model=self.model_name or 'anthropic',
        )

        content_blocks = result.get('content', [])
        texts = [b.get('text', '') for b in content_blocks if b.get('type') == 'text']
        return '\n'.join(texts).strip()

    def _call_stepfun(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """POST to StepFun Step 3.5 Flash API (OpenAI-compatible format).

        Step 3.5 Flash: 196B-parameter sparse MoE with 11B active params.
        Excels at coding (86.4% LiveCodeBench), math, agent tasks, and
        tool use.  100-350 tok/s throughput via Multi-Token Prediction.

        Providers:
          - StepFun direct: STEPFUN_API_KEY + https://api.stepfun.ai/v1
          - OpenRouter:     OPENROUTER_API_KEY (free tier available)
        """
        # Support OpenRouter as fallback provider
        api_key = self._api_key or os.environ.get('STEPFUN_API_KEY', '')
        url = STEPFUN_API_URL
        model = self.model_name or 'step-3.5-flash'

        if not api_key and os.environ.get('OPENROUTER_API_KEY'):
            api_key = os.environ['OPENROUTER_API_KEY']
            url = 'https://openrouter.ai/api/v1/chat/completions'
            model = 'stepfun/step-3.5-flash'

        if not api_key:
            raise ValueError("STEPFUN_API_KEY (or OPENROUTER_API_KEY) not set")

        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({'role': 'system', 'content': system_prompt})
        messages.append({'role': 'user', 'content': prompt})

        payload = {
            'model': model,
            'messages': messages,
            'temperature': 0.3,
            'max_tokens': 2048,
        }

        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {api_key}',
                'User-Agent': 'Donjon/1.0',
            },
            method='POST',
        )

        with urllib.request.urlopen(req, timeout=90, context=ctx) as resp:  # nosec B310 -- URL constructed from hardcoded STEPFUN_API_URL/OpenRouter constants
            result = json.loads(resp.read().decode('utf-8'))

        choices = result.get('choices', [])
        if choices:
            return choices[0].get('message', {}).get('content', '').strip()
        return ''

    def _call_gemini(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """POST to the Google Gemini generateContent endpoint (stdlib only).

        Uses the v1beta REST API with an API key query parameter.
        Supports Gemini 2.5 Flash (fast, 1M context, free tier: 500 req/day).
        """
        api_key = self._api_key or os.environ.get('GEMINI_API_KEY', '')
        if not api_key:
            raise ValueError("GEMINI_API_KEY environment variable is not set")

        model = self.model_name or 'gemini-2.5-flash'
        url = f"{GEMINI_API_URL}/{model}:generateContent?key={api_key}"

        # Build Gemini-format request
        contents: List[Dict] = []
        if system_prompt:
            contents.append({
                'role': 'user',
                'parts': [{'text': f"[System Instructions]\n{system_prompt}\n\n[User Query]\n{prompt}"}],
            })
        else:
            contents.append({
                'role': 'user',
                'parts': [{'text': prompt}],
            })

        payload = {
            'contents': contents,
            'generationConfig': {
                'temperature': 0.3,
                'maxOutputTokens': 2048,
            },
        }

        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'User-Agent': 'Donjon/1.0',
            },
            method='POST',
        )

        with urllib.request.urlopen(req, timeout=90, context=ctx) as resp:  # nosec B310 -- URL constructed from hardcoded GEMINI_API_URL constant
            result = json.loads(resp.read().decode('utf-8'))

        # Parse Gemini response format
        candidates = result.get('candidates', [])
        if candidates:
            content = candidates[0].get('content', {})
            parts = content.get('parts', [])
            texts = [p.get('text', '') for p in parts if 'text' in p]
            return '\n'.join(texts).strip()
        return ''

    def _call_openai(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """POST to an OpenAI-compatible chat completions endpoint."""
        api_key = self._api_key or os.environ.get('OPENAI_API_KEY', '')
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable is not set")

        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({'role': 'system', 'content': system_prompt})
        messages.append({'role': 'user', 'content': prompt})

        payload = {
            'model': self.model_name or 'gpt-4',
            'messages': messages,
            'temperature': 0.3,
            'max_tokens': 2048,
        }

        url = _validate_url(self._api_url or OPENAI_API_URL)
        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode('utf-8'),
            headers={
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {api_key}',
                'User-Agent': 'Donjon/1.0',
            },
            method='POST',
        )

        with urllib.request.urlopen(req, timeout=90, context=ctx) as resp:
            result = json.loads(resp.read().decode('utf-8'))

        # Track usage (OpenAI format)
        usage = result.get('usage', {})
        if usage:
            self._record_usage(
                input_tokens=usage.get('prompt_tokens', 0),
                output_tokens=usage.get('completion_tokens', 0),
                model=self.model_name or 'openai',
            )

        choices = result.get('choices', [])
        if choices:
            return choices[0].get('message', {}).get('content', '').strip()
        return ''

    def _call_bedrock(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Call AWS Bedrock InvokeModel using SigV4 auth (stdlib only, no boto3).

        Uses the Anthropic Messages format via Bedrock's /invoke endpoint.
        Tracks input/output tokens for metered billing.
        """
        import hashlib
        import hmac
        from datetime import datetime as dt

        region = self._aws_region or 'us-east-1'
        model_id = self.model_name or _BEDROCK_MODELS['claude-sonnet']
        service = 'bedrock'

        # Build Anthropic-format payload
        messages = [{'role': 'user', 'content': prompt}]
        body = {
            'anthropic_version': 'bedrock-2023-05-31',
            'max_tokens': 2048,
            'messages': messages,
            'temperature': 0.3,
        }
        if system_prompt:
            body['system'] = system_prompt

        body_bytes = json.dumps(body).encode('utf-8')

        # SigV4 signing
        now = dt.utcnow()
        datestamp = now.strftime('%Y%m%d')
        amz_date = now.strftime('%Y%m%dT%H%M%SZ')

        host = f'bedrock-runtime.{region}.amazonaws.com'
        endpoint = f'https://{host}/model/{urllib.parse.quote(model_id, safe="")}/invoke'
        canonical_uri = f'/model/{urllib.parse.quote(model_id, safe="")}/invoke'

        content_hash = hashlib.sha256(body_bytes).hexdigest()

        headers_to_sign = {
            'content-type': 'application/json',
            'host': host,
            'x-amz-date': amz_date,
            'x-amz-content-sha256': content_hash,
        }
        if self._aws_session_token:
            headers_to_sign['x-amz-security-token'] = self._aws_session_token

        signed_headers = ';'.join(sorted(headers_to_sign.keys()))
        canonical_headers = ''.join(
            f'{k}:{v}\n' for k, v in sorted(headers_to_sign.items())
        )
        canonical_request = '\n'.join([
            'POST', canonical_uri, '',
            canonical_headers, signed_headers, content_hash,
        ])

        credential_scope = f'{datestamp}/{region}/{service}/aws4_request'
        string_to_sign = '\n'.join([
            'AWS4-HMAC-SHA256', amz_date, credential_scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        ])

        def _sign(key, msg):
            return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

        k_date = _sign(('AWS4' + (self._aws_secret_key or '')).encode('utf-8'), datestamp)
        k_region = hmac.new(k_date, region.encode('utf-8'), hashlib.sha256).digest()
        k_service = hmac.new(k_region, service.encode('utf-8'), hashlib.sha256).digest()
        k_signing = hmac.new(k_service, b'aws4_request', hashlib.sha256).digest()
        signature = hmac.new(k_signing, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

        auth_header = (
            f'AWS4-HMAC-SHA256 Credential={self._aws_access_key}/{credential_scope}, '
            f'SignedHeaders={signed_headers}, Signature={signature}'
        )

        req_headers = {
            'Content-Type': 'application/json',
            'Host': host,
            'X-Amz-Date': amz_date,
            'X-Amz-Content-Sha256': content_hash,
            'Authorization': auth_header,
            'User-Agent': 'Donjon/1.0',
        }
        if self._aws_session_token:
            req_headers['X-Amz-Security-Token'] = self._aws_session_token

        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            endpoint, data=body_bytes, headers=req_headers, method='POST',
        )

        with urllib.request.urlopen(req, timeout=120, context=ctx) as resp:
            result = json.loads(resp.read().decode('utf-8'))

        # Track usage for billing
        usage = result.get('usage', {})
        self._record_usage(
            input_tokens=usage.get('input_tokens', 0),
            output_tokens=usage.get('output_tokens', 0),
            model=model_id,
        )

        # Parse Anthropic response format
        content_blocks = result.get('content', [])
        texts = [b.get('text', '') for b in content_blocks if b.get('type') == 'text']
        return '\n'.join(texts).strip()

    def _record_usage(self, input_tokens: int, output_tokens: int, model: str) -> None:
        """Record token usage for metered billing."""
        self._total_input_tokens += input_tokens
        self._total_output_tokens += output_tokens
        self._total_requests += 1
        entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'backend': self.backend,
            'model': model,
            'input_tokens': input_tokens,
            'output_tokens': output_tokens,
        }
        self._usage_log.append(entry)
        # Persist to usage file for billing aggregation
        try:
            usage_path = (self._CONFIG_PATH.parent / 'ai_usage.jsonl') if self._CONFIG_PATH else Path('data/ai_usage.jsonl')
            with open(usage_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry) + '\n')
        except Exception:
            pass

    def get_usage(self) -> Dict:
        """Return cumulative token usage for billing."""
        return {
            'total_requests': self._total_requests,
            'total_input_tokens': self._total_input_tokens,
            'total_output_tokens': self._total_output_tokens,
            'total_tokens': self._total_input_tokens + self._total_output_tokens,
            'backend': self.backend,
            'model': self.model_name,
            'session_log': self._usage_log[-20:],  # Last 20 entries
        }

    def _call_ai(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Route to the detected backend and return the raw text response."""
        if self.backend == 'ollama':
            return self._call_ollama(prompt, system_prompt)
        elif self.backend == 'bedrock':
            return self._call_bedrock(prompt, system_prompt)
        elif self.backend == 'stepfun':
            return self._call_stepfun(prompt, system_prompt)
        elif self.backend == 'anthropic':
            return self._call_anthropic(prompt, system_prompt)
        elif self.backend == 'gemini':
            return self._call_gemini(prompt, system_prompt)
        elif self.backend == 'openai':
            return self._call_openai(prompt, system_prompt)
        return ''

    # ------------------------------------------------------------------
    # JSON extraction helper
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_json(text: str) -> Any:
        """Try to extract a JSON object or array from raw LLM output."""
        if not text:
            return None
        # Strip markdown fences if present
        cleaned = text.strip()
        if cleaned.startswith('```'):
            lines = cleaned.split('\n')
            lines = [l for l in lines if not l.strip().startswith('```')]
            cleaned = '\n'.join(lines).strip()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass
        # Try to find first { or [ and last } or ]
        for start_char, end_char in [('{', '}'), ('[', ']')]:
            start = cleaned.find(start_char)
            end = cleaned.rfind(end_char)
            if start != -1 and end != -1 and end > start:
                try:
                    return json.loads(cleaned[start:end + 1])
                except json.JSONDecodeError:
                    continue
        return None

    # ------------------------------------------------------------------
    # High-level analysis methods
    # ------------------------------------------------------------------

    def analyze_finding(self, finding: Dict) -> Dict:
        """
        Analyse a single security finding.

        Returns a dict with keys: severity_validated, exploit_likelihood,
        business_impact, attack_vector, mitre_techniques, confidence, notes.
        Falls back to template analysis if no LLM is available.
        """
        if self.backend == 'template':
            return self._template_analyze_finding(finding)

        finding_json = json.dumps(finding, indent=2, default=str)
        prompt = FINDING_ANALYSIS_PROMPT.format(finding_json=finding_json)

        try:
            raw = self._call_ai(prompt, system_prompt=SYSTEM_PROMPT)
            parsed = self._extract_json(raw)
            if isinstance(parsed, dict):
                parsed['_ai_generated'] = True
                parsed['_backend'] = self.backend
                parsed['_disclaimer'] = AI_DISCLAIMER.strip()
                return parsed
        except Exception as exc:
            logger.warning("AI finding analysis failed (%s), using template: %s", self.backend, exc)

        return self._template_analyze_finding(finding)

    def triage_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Prioritise a batch of findings from most to least urgent.

        Returns a list of dicts with keys: title, rank, reasoning,
        recommended_sla.
        """
        if self.backend == 'template':
            return self._template_triage_findings(findings)

        findings_json = json.dumps(findings, indent=2, default=str)
        prompt = TRIAGE_PROMPT.format(findings_json=findings_json)

        try:
            raw = self._call_ai(prompt, system_prompt=SYSTEM_PROMPT)
            parsed = self._extract_json(raw)
            if isinstance(parsed, list) and parsed:
                for item in parsed:
                    item['_ai_generated'] = True
                return parsed
        except Exception as exc:
            logger.warning("AI triage failed (%s), using template: %s", self.backend, exc)

        return self._template_triage_findings(findings)

    def generate_remediation(self, finding: Dict) -> str:
        """
        Generate step-by-step remediation instructions.

        Returns a formatted string (or JSON string when AI-generated).
        """
        if self.backend == 'template':
            return self._template_generate_remediation(finding)

        finding_json = json.dumps(finding, indent=2, default=str)
        prompt = REMEDIATION_PROMPT.format(finding_json=finding_json)

        try:
            raw = self._call_ai(prompt, system_prompt=SYSTEM_PROMPT)
            if raw:
                return AI_DISCLAIMER + raw
        except Exception as exc:
            logger.warning("AI remediation failed (%s), using template: %s", self.backend, exc)

        return self._template_generate_remediation(finding)

    def summarize_scan(self, session_id: str) -> str:
        """
        Generate an executive-friendly summary for a scan session.

        Pulls scan data from the evidence manager when available.
        """
        scan_data = self._load_scan_data(session_id)
        if not scan_data:
            return f"No scan data found for session {session_id}."

        if self.backend == 'template':
            return self._template_summarize_scan(scan_data)

        scan_data_json = json.dumps(scan_data, indent=2, default=str)
        prompt = SCAN_SUMMARY_PROMPT.format(scan_data_json=scan_data_json)

        try:
            raw = self._call_ai(prompt, system_prompt=SYSTEM_PROMPT)
            if raw:
                return AI_DISCLAIMER + raw
        except Exception as exc:
            logger.warning("AI scan summary failed (%s), using template: %s", self.backend, exc)

        return self._template_summarize_scan(scan_data)

    def query(self, question: str, context: Optional[Dict] = None) -> str:
        """
        Answer a natural-language question, optionally with scan context.
        """
        if self.backend == 'template':
            return self._template_query(question, context)

        context_json = json.dumps(context or {}, indent=2, default=str)
        prompt = QUERY_PROMPT.format(question=question, context_json=context_json)

        try:
            raw = self._call_ai(prompt, system_prompt=SYSTEM_PROMPT)
            if raw:
                return AI_DISCLAIMER + raw
        except Exception as exc:
            logger.warning("AI query failed (%s), using template: %s", self.backend, exc)

        return self._template_query(question, context)

    # ------------------------------------------------------------------
    # Scan data loader
    # ------------------------------------------------------------------

    def _load_scan_data(self, session_id: str) -> Optional[Dict]:
        """Load scan session data from the evidence manager."""
        try:
            try:
                from .evidence import get_evidence_manager
            except ImportError:
                from evidence import get_evidence_manager

            em = get_evidence_manager()
            summary = em.get_session_summary(session_id)
            if not summary:
                return None

            findings = em.get_findings_for_session(session_id)
            return {
                'session_id': session_id,
                'session': summary.get('session', {}),
                'evidence_count': summary.get('evidence_count', 0),
                'findings_by_severity': summary.get('findings_by_severity', {}),
                'findings': findings,
                'total_findings': len(findings),
            }
        except Exception as exc:
            logger.debug("Could not load scan data for %s: %s", session_id, exc)
            return None

    # ------------------------------------------------------------------
    # Template fallback implementations
    # ------------------------------------------------------------------

    def _template_analyze_finding(self, finding: Dict) -> Dict:
        """Rule-based finding analysis (no LLM required)."""
        severity = finding.get('severity', 'MEDIUM').upper()
        cvss = float(finding.get('cvss_score', 0.0))
        epss = float(finding.get('epss_score', 0.0))
        kev = str(finding.get('kev_status', '')).lower() in ('true', '1', 'yes')
        finding_type = finding.get('finding_type', 'unknown')

        # Validate severity against CVSS
        if cvss >= 9.0:
            validated = 'CRITICAL'
        elif cvss >= 7.0:
            validated = 'HIGH'
        elif cvss >= 4.0:
            validated = 'MEDIUM'
        elif cvss > 0:
            validated = 'LOW'
        else:
            validated = severity

        # Exploit likelihood
        if kev:
            exploit_likelihood = 'CONFIRMED'
        elif epss >= 0.7:
            exploit_likelihood = 'HIGH'
        elif epss >= 0.3:
            exploit_likelihood = 'MEDIUM'
        elif epss >= 0.1:
            exploit_likelihood = 'LOW'
        else:
            exploit_likelihood = 'THEORETICAL'

        # Business impact
        impact_map = {
            'CRITICAL': (
                "Exploitation could result in complete system compromise, "
                "data breach, or significant service disruption."
            ),
            'HIGH': (
                "Exploitation could lead to unauthorized data access, "
                "privilege escalation, or partial service compromise."
            ),
            'MEDIUM': (
                "Exploitation could contribute to a broader attack chain "
                "or expose limited sensitive information."
            ),
            'LOW': (
                "Minimal direct business impact, but contributes to overall "
                "attack surface."
            ),
            'INFO': "Informational finding with no direct exploitable risk.",
        }

        return {
            'severity_validated': validated,
            'exploit_likelihood': exploit_likelihood,
            'business_impact': impact_map.get(validated, impact_map['MEDIUM']),
            'attack_vector': f"Exploitation of {finding_type} on "
                             f"{finding.get('affected_asset', 'target asset')}",
            'mitre_techniques': [],
            'confidence': 0.6,
            'notes': f"Template-based analysis (no LLM). CVSS={cvss}, EPSS={epss:.2f}, KEV={kev}.",
            '_ai_generated': False,
            '_backend': 'template',
        }

    def _template_triage_findings(self, findings: List[Dict]) -> List[Dict]:
        """Sort findings by severity/CVSS/EPSS without an LLM."""
        if not findings:
            return []

        def _score(f: Dict) -> float:
            sev_val = _SEVERITY_ORDER.get(f.get('severity', 'INFO').upper(), 1)
            cvss = float(f.get('cvss_score', 0.0))
            epss = float(f.get('epss_score', 0.0))
            kev = 2.0 if str(f.get('kev_status', '')).lower() in ('true', '1', 'yes') else 0.0
            return sev_val * 2.0 + cvss + epss * 1.5 + kev

        scored = sorted(findings, key=_score, reverse=True)
        result = []
        for rank, f in enumerate(scored, start=1):
            severity = f.get('severity', 'MEDIUM').upper()
            result.append({
                'title': f.get('title', 'Unknown'),
                'rank': rank,
                'reasoning': (
                    f"Severity {severity}, CVSS {f.get('cvss_score', 0.0)}, "
                    f"EPSS {f.get('epss_score', 0.0):.2f}"
                ),
                'recommended_sla': _SLA_MAP.get(severity, 'STANDARD (30d)'),
                '_ai_generated': False,
            })
        return result

    def _template_generate_remediation(self, finding: Dict) -> str:
        """Generate basic remediation steps from finding metadata."""
        title = finding.get('title', 'Unknown Finding')
        severity = finding.get('severity', 'MEDIUM').upper()
        finding_type = finding.get('finding_type', 'unknown')
        existing = finding.get('remediation', '')

        lines = [
            f"Remediation Plan: {title}",
            f"Priority: {severity}",
            "=" * 55,
            "",
        ]

        if existing:
            lines.append("Recommended Steps:")
            lines.append(f"  1. {existing}")
            lines.append("  2. Validate the fix in a staging environment")
            lines.append("  3. Apply the fix in production during a maintenance window")
            lines.append("  4. Re-scan the affected asset to confirm remediation")
            lines.append("  5. Document the change for audit trail")
        else:
            lines.append("Recommended Steps:")
            lines.append("  1. Research the specific vulnerability and vendor advisories")
            lines.append("  2. Apply available patches or configuration changes")
            lines.append("  3. Implement compensating controls if immediate patching is not feasible")
            lines.append("  4. Test the fix in a non-production environment first")
            lines.append("  5. Re-scan to verify remediation effectiveness")
            lines.append("  6. Document all actions taken for compliance records")

        lines.append("")
        sla = _SLA_MAP.get(severity, 'STANDARD (30d)')
        lines.append(f"Target SLA: {sla}")

        lines.extend([
            "",
            "Verification:",
            "  - Re-run the security scan against the affected asset",
            "  - Confirm the finding no longer appears in results",
            "  - Document remediation actions for audit trail",
        ])

        return '\n'.join(lines)

    def _template_summarize_scan(self, scan_data: Dict) -> str:
        """Generate a structured executive summary without any LLM."""
        by_sev = scan_data.get('findings_by_severity', {})
        total = scan_data.get('total_findings', 0)
        session_id = scan_data.get('session_id', 'UNKNOWN')

        critical = by_sev.get('CRITICAL', 0)
        high = by_sev.get('HIGH', 0)
        medium = by_sev.get('MEDIUM', 0)
        low = by_sev.get('LOW', 0)
        info = by_sev.get('INFO', 0)

        if critical > 0:
            posture = "CRITICAL"
            headline = "Critical vulnerabilities require immediate attention."
        elif high > 0:
            posture = "HIGH"
            headline = "Significant risks detected requiring prompt remediation."
        elif medium > 0:
            posture = "MODERATE"
            headline = "Moderate risks identified; remediation recommended within 30 days."
        elif low > 0:
            posture = "LOW"
            headline = "Minor issues found; address during normal maintenance."
        else:
            posture = "MINIMAL"
            headline = "No significant vulnerabilities identified."

        lines = [
            f"EXECUTIVE SUMMARY - Session {session_id}",
            f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "=" * 60,
            "",
            f"Risk Posture: {posture}",
            f"  {headline}",
            "",
            "Findings:",
            f"  Total:          {total}",
            f"  Critical:       {critical}",
            f"  High:           {high}",
            f"  Medium:         {medium}",
            f"  Low:            {low}",
            f"  Informational:  {info}",
            "",
        ]

        if critical > 0 or high > 0:
            lines.append("Priority Actions:")
            if critical > 0:
                lines.append(f"  - Address {critical} CRITICAL finding(s) within 24 hours")
            if high > 0:
                lines.append(f"  - Remediate {high} HIGH finding(s) within 7 days")
            if medium > 0:
                lines.append(f"  - Plan remediation for {medium} MEDIUM finding(s)")
            lines.append("")

        lines.append("(Template-generated summary - no AI backend available)")
        return '\n'.join(lines)

    def _template_query(self, question: str, context: Optional[Dict] = None) -> str:
        """Provide a basic response when no LLM is available."""
        lines = [
            "AI query engine is running in template mode (no LLM backend detected).",
            "",
            f"Your question: {question}",
            "",
        ]

        if context:
            findings = context.get('findings', [])
            if findings:
                lines.append(f"Context contains {len(findings)} finding(s).")
                severities: Dict[str, int] = {}
                for f in findings:
                    s = f.get('severity', 'UNKNOWN')
                    severities[s] = severities.get(s, 0) + 1
                lines.append("Severity breakdown:")
                for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'):
                    count = severities.get(sev, 0)
                    if count:
                        lines.append(f"  {sev}: {count}")
                lines.append("")

        lines.extend([
            "To enable AI-powered answers, configure one of:",
            "  1. Install Ollama locally with Step 3.5 Flash (air-gapped, recommended)",
            "  2. Set STEPFUN_API_KEY for Step 3.5 Flash cloud API",
            "  3. Set ANTHROPIC_API_KEY for Anthropic Claude",
            "  4. Set GEMINI_API_KEY for Google Gemini (fast & free tier)",
            "  5. Set OPENAI_API_KEY for OpenAI GPT-4",
        ])
        return '\n'.join(lines)

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def get_status(self) -> Dict:
        """Return current engine status for diagnostics."""
        return {
            'backend': self.backend,
            'model_name': self.model_name,
            'ai_available': self.backend != 'template',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }

    def __repr__(self) -> str:
        return f"AIEngine(backend='{self.backend}', model={self.model_name!r})"


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------
_ai_engine: Optional[AIEngine] = None


def get_ai_engine() -> AIEngine:
    """Get the singleton AIEngine instance."""
    global _ai_engine
    if _ai_engine is None:
        _ai_engine = AIEngine()
    return _ai_engine


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    engine = get_ai_engine()
    print(f"AI Engine: {engine}")
    print(f"Status: {json.dumps(engine.get_status(), indent=2)}")

    sample_finding = {
        'title': 'SQL Injection in Login Form',
        'severity': 'CRITICAL',
        'cvss_score': 9.8,
        'epss_score': 0.92,
        'kev_status': 'true',
        'finding_type': 'sql_injection',
        'affected_asset': '10.0.0.5',
        'description': 'Unsanitized user input in login POST parameter allows SQL injection.',
        'remediation': 'Use parameterized queries for all database operations.',
    }

    print("\n--- Finding Analysis ---")
    analysis = engine.analyze_finding(sample_finding)
    print(json.dumps(analysis, indent=2))

    print("\n--- Remediation ---")
    remediation = engine.generate_remediation(sample_finding)
    print(remediation)

    print("\n--- Triage ---")
    triaged = engine.triage_findings([sample_finding])
    print(json.dumps(triaged, indent=2))

    print("\n--- Query ---")
    answer = engine.query("What is the most critical finding?", {'findings': [sample_finding]})
    print(answer)
