# Getting Started with GhidrAssist

This guide helps you install GhidrAssist, configure an LLM provider, and run your first analysis in Ghidra.

## Prerequisites

Before installing GhidrAssist, ensure you have:

- **Ghidra**: Version 11.0 or higher
- **Internet connection**: For cloud providers or downloading local models
- **Python (optional)**: For some local tooling, depending on your MCP server setup

## Installation

GhidrAssist is installed as a Ghidra extension.

### Step 1: Install the Extension

**Option A: Extension Manager (Recommended)**

1. Download the GhidrAssist release ZIP
2. Open Ghidra
3. Go to **File → Install Extensions**
4. Click the **+** button and select the ZIP
5. Enable the extension and restart Ghidra

**Option B: Manual Install**

1. Copy the release ZIP into:
   - `Ghidra_Install/Extensions/Ghidra/`
2. Restart Ghidra
3. Enable the extension in **File → Install Extensions**

### Step 2: Enable the Plugin

1. Open or create a project
2. Launch **CodeBrowser**
3. Go to **File → Configure → Miscellaneous**
4. Check **Enable GhidrAssist**

### Step 3: Open GhidrAssist

1. In CodeBrowser, open **Window → GhidrAssist**
2. The GhidrAssist panel appears with the tab interface

## Building from Source (Ghidra 12.1.4)

This section is for users who download the repository using **Code → Download ZIP** and compile the extension themselves. You do not need a Git clone or a persistent checkout.

### Build requirements

- An installed and working **Ghidra 12.1.4** distribution (the environment used to test this build).
- A **JDK compatible with that Ghidra installation** (Ghidra 12.1.4 uses Java 21 or newer).
- A compatible **Gradle** version. This project does not pin or include its own Gradle wrapper. Its `build.gradle` imports `support/buildExtension.gradle` from the selected Ghidra installation.
- Internet access for the initial Gradle wrapper download and external project dependencies.

**Verified example:** Ghidra 12.1.4 + Gradle 9.7.1 on Linux. For other Ghidra versions, check the `application.gradle.version` (or equivalent Gradle requirement) declared in `<GHIDRA_INSTALL_DIR>/Ghidra/application.properties`. Do not assume the Gradle packaged by your operating system is recent enough.

### Recommended: use the Gradle wrapper included with Ghidra

No system-wide Gradle installation is necessary. Unzip the **repository source ZIP**, open a terminal in its root directory (where `build.gradle` is located), and run:

```bash
export GHIDRA_INSTALL_DIR="/absolute/path/to/ghidra_12.1.4_PUBLIC"
cd "/path/to/extracted/GhidrAssist"
grep '^application.gradle' "$GHIDRA_INSTALL_DIR/Ghidra/application.properties"
"$GHIDRA_INSTALL_DIR/support/gradle/gradlew" --version
"$GHIDRA_INSTALL_DIR/support/gradle/gradlew" --no-daemon clean buildExtension
```

Replace the example paths with your own. On Windows, use `support\\gradle\\gradlew.bat` from the Ghidra installation and set `GHIDRA_INSTALL_DIR` in your shell.

The build produces the **installable extension ZIP** in `dist/`. Install that generated ZIP using Ghidra's extension manager as described in [Installation](#installation). Do not install the source ZIP downloaded from GitHub.

### Alternative A: use a system-wide Gradle installation

If you already have Gradle installed, check its version:

```bash
gradle --version
```

Compare it with the Gradle requirement in your Ghidra installation. If compatible, from the extracted GhidrAssist source directory run:

```bash
export GHIDRA_INSTALL_DIR="/absolute/path/to/ghidra_12.1.4_PUBLIC"
gradle --no-daemon clean buildExtension
```

A Gradle installed through a Linux package manager may be older than the version required by newer Ghidra releases. Installing or upgrading system-wide Gradle is **optional**; the Ghidra wrapper is usually simpler.

### Alternative B: install Gradle in a separate directory

If you prefer to keep Gradle out of the system `PATH`, download a suitable binary distribution from the [official Gradle releases](https://gradle.org/releases/) and extract it, for example, into `~/tools/gradle-9.7.1/`. Replace `9.7.1` with the version appropriate for your Ghidra installation.

From the GhidrAssist source directory:

```bash
export GHIDRA_INSTALL_DIR="/absolute/path/to/ghidra_12.1.4_PUBLIC"
"$HOME/tools/gradle-9.7.1/bin/gradle" --version
"$HOME/tools/gradle-9.7.1/bin/gradle" --no-daemon clean buildExtension
```

This avoids changing the system's Gradle version. Gradle may still use the normal `~/.gradle` cache regardless of which executable you choose.

### Troubleshooting builds

- **`GHIDRA_INSTALL_DIR is not defined!`** — set the variable to the root of the *Ghidra installation*, not the GhidrAssist source directory.
- **Gradle compatibility error** — use the wrapper shipped with the selected Ghidra, or install a compatible version.
- **Java/JDK error** — verify `java -version` and choose a JDK supported by the installed Ghidra.
- **Build completes but there is nothing to install** — look in `dist/` for the ZIP generated by `buildExtension`, rather than using the source ZIP.
- **Dependency download failure** — check internet connectivity and Maven repository access on the first build.

## Initial Configuration

You need to configure at least one LLM provider.

### Accessing Settings

1. In the GhidrAssist panel, click the **Settings** tab
2. The LLM Providers section appears at the top

## Setting Up an LLM Provider

GhidrAssist supports multiple providers. Choose the one that fits your needs:

Recommended open-weight families are **GLM, Qwen, DeepSeek, Nemotron, Gemma, and Muse**; hosted frontier options include **Opus, Sonnet, and GPT**. See the [model guidance](index.md#recommended-models) for selection criteria. Family names are recommendations: the **Model** field requires the exact ID or tag from your provider.

### Option 1: Ollama (Local, Free, Private)

Ollama runs models locally on your machine.

**Step 1: Install Ollama**

```bash
# Linux/macOS
curl -fsSL https://ollama.ai/install.sh | sh

# Windows: Download from https://ollama.ai/download
```

**Step 2: Pull a Model**

Choose a model supported by your runtime from the [Ollama library](https://ollama.com/library), with memory and context requirements that fit your machine. Replace `MODEL_TAG` below with its exact tag.

```bash
# Download the selected model
ollama pull MODEL_TAG

# Find the installed tag to use in Settings
ollama list

# Start the server
ollama serve
```

**Step 3: Configure in GhidrAssist**

1. In Settings, click **Add** in LLM Providers
2. Fill in:
   - **Name**: `Ollama Local`
   - **Type**: `Ollama`
   - **Model**: The exact installed tag shown by `ollama list`
   - **URL**: `http://localhost:11434`
   - **API Key**: Leave empty
   - **Max Tokens**: `16384`
3. Click **Save**
4. Click **Test**

### Option 2: OpenAI Platform API

Use OpenAI models with a paid API key.

**Step 1: Get an API Key**

1. Go to [platform.openai.com](https://platform.openai.com/)
2. Create an API key from the dashboard

**Step 2: Configure in GhidrAssist**

1. Click **Add** in LLM Providers
2. Fill in:
   - **Name**: `OpenAI`
   - **Type**: `OpenAI Platform API`
   - **Model**: The exact GPT model ID available from your provider's model catalog
   - **URL**: Leave empty (default)
   - **API Key**: Paste your API key
   - **Max Tokens**: `20000`
3. Click **Save**
4. Click **Test**

### Option 3: Anthropic Platform API

Use Claude models with a paid API key.

**Step 1: Get an API Key**

1. Go to [console.anthropic.com](https://console.anthropic.com/)
2. Create an API key

**Step 2: Configure in GhidrAssist**

1. Click **Add** in LLM Providers
2. Fill in:
   - **Name**: `Anthropic Claude`
   - **Type**: `Anthropic Platform API`
   - **Model**: The exact Sonnet or Opus model ID available from your provider's model catalog
   - **URL**: Leave empty (default)
   - **API Key**: Paste your API key
   - **Max Tokens**: `20000`
3. Click **Save**
4. Click **Test**

### Option 4: OAuth Providers (Claude Pro/Max or ChatGPT Pro/Plus)

If you have a Claude Pro/Max or ChatGPT Pro/Plus subscription, use OAuth instead of an API key.

**Claude Pro/Max:**

1. Click **Add** in LLM Providers
2. Select **Type**: `Anthropic OAuth`
3. Enter **Name** and the exact **Model** ID for Sonnet or Opus supported by this provider
4. Click **Authenticate**
5. A browser window opens for login
6. After authorization, credentials are saved automatically
7. Click **Save**

**ChatGPT Pro/Plus:**

1. Click **Add** in LLM Providers
2. Select **Type**: `OpenAI OAuth`
3. Enter **Name** and the exact **Model** ID for GPT supported by this provider
4. Click **Authenticate**
5. A browser window opens for login
6. After authorization, credentials are saved automatically
7. Click **Save**

### Setting the Active Provider

1. Use the **Active Provider** dropdown at the bottom of the LLM Providers section
2. Select the provider you want to use

## Your First Analysis

### Step 1: Load a Binary

1. Open a binary in Ghidra
2. Wait for auto-analysis to complete

### Step 2: Navigate to a Function

1. In the Functions window, click a function
2. Or press **G** and enter an address

### Step 3: Explain the Function

1. Open the GhidrAssist panel
2. Click the **Explain** tab
3. Click **Explain Function**
4. Wait for the explanation to stream in

### Step 4: Ask a Question

1. Switch to the **Query** tab
2. Type a question, for example:
   - "What does this function do?"
   - "Are there any security concerns here?"
   - "What functions does this call?"
3. Click **Submit**
4. Watch the response stream in

## Next Steps

Explore these guides:

- [Explain Workflow](workflows/explain-workflow.md)
- [Query Workflow](workflows/query-workflow.md)
- [Semantic Graph Workflow](workflows/semantic-graph-workflow.md)
- [Settings Reference](tabs/settings-tab.md)

## Troubleshooting

### "Connection failed" when testing provider

- **Ollama**: Ensure `ollama serve` is running
- **Cloud providers**: Verify your API key is correct
- **Network issues**: Check firewall and proxy settings

### No response from LLM

- Check **Window → Console** in Ghidra for errors
- Verify the model name is correct
- Ensure you have sufficient API credits

### Plugin not appearing

- Restart Ghidra after installation
- Confirm the extension is enabled
- Ensure it is enabled in **File → Configure → Miscellaneous**

### Slow responses

- Local models: Use a smaller model or a GPU
- Cloud models: Reasoning models are slower by design
- Large functions: Analyze smaller functions first
