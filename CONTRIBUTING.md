# CONTRIBUTING

1. **Build the Action**: Run `npm install` to install dependencies, then run `npm run build` to compile TypeScript to JavaScript.
2. **Prepare the Action**: Run `npm run prepare` to bundle the action using `ncc`.
3. **Include the Action in Your Workflow**: Use the `uses: ./` syntax to reference the action in your workflow.
