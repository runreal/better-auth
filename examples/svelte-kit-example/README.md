# SvelteKit Better Auth Example


This is an example of how to use Better Auth with SvelteKit.

**Implements the following features:**
Email & Password . <u>Social Sign-in with Google</u> . Passkeys . Email Verification . Password Reset . Two Factor Authentication . Profile Update . Session Management

## How to run

1. Clone the code sandbox (or the repo) and open it in your code editor
2. Move .env.example to .env and provide necessary variables
3. Run the following commands
   ```bash
   cd /path/to/better-auth/ # Project root of this better-auth repo, not the root of this example
   pnpm install
   pnpm build
   cd ./examples/svelte-kit-example/ # The root of this example project
   pnpm migrate
   pnpm dev
   ```
4. Open the browser and navigate to `http://localhost:3000`

