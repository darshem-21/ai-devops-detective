<<<<<<< HEAD
# AI DevOps Detective

A browser-based starter project combining:
- Kubernetes incident diagnosis from pasted logs/events (read-only; no live cluster connection by default)
- Cost optimization analysis using sample workload metrics or submitted JSON
- Optional AI explanations through OpenRouter
- FastAPI backend + responsive HTML/CSS/JS dashboard
- GitHub Actions tests and Docker image build/publish to GHCR

## Quick start online
1. Create a GitHub repository named `ai-devops-detective`.
2. Upload these files using GitHub's web UI, or open a GitHub Codespace and upload/unzip the project.
3. Add `OPENROUTER_API_KEY` only if you want AI-generated explanations. The app works without it using deterministic rules.
4. Deploy on Render from your GitHub repository:
   - New > Web Service
   - Runtime: Python
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - Add environment variable `OPENROUTER_API_KEY` (optional).
   - Choose Free if available in your account/region. Free services may sleep when idle and are not production-grade.
5. Visit `https://YOUR-SERVICE.onrender.com/` and `/health`.

## GitHub Actions
- Pull requests and pushes run tests.
- Pushes to `main` build a Docker image and publish it to GitHub Container Registry (GHCR).
- In repository Settings > Actions > General, allow GitHub Actions to create packages if needed.
- The published image is `ghcr.io/OWNER/REPO:latest` and `ghcr.io/OWNER/REPO:<commit-sha>`.
- Public repositories generally have the most generous GitHub Actions minutes for standard runners; confirm current limits in GitHub billing docs.

## Kubernetes practice (browser only)
Use Killercoda: https://killercoda.com/ and Kubernetes learning environment docs: https://kubernetes.io/docs/setup/learning-environment/
The starter app deliberately does not connect to a real cluster or run `kubectl` commands. Paste logs/events into the dashboard. To add a live read-only integration later, run the backend inside a cluster with a narrowly scoped ServiceAccount/RBAC policy and never expose kubeconfig or cluster credentials in frontend code.

## Cost model
The included cost estimator is a learning estimate based on sample hourly rates and utilization. It is not a cloud bill and should not be presented as exact provider charges. Replace sample inputs with OpenCost or cloud billing data for real analysis.

## Security notes
- Never commit API keys, kubeconfig files, cloud credentials, or `.env` files.
- Configure secrets in Render Environment settings and GitHub repository Actions secrets.
- AI output is advisory; review commands before executing. The app never executes suggested commands.
=======
# ai-devops-detective
>>>>>>> 1eb8579483978e6c9ac3330c73e1695ad91236a4
