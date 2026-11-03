export class ToolError extends Error {
  constructor(readonly code: string, message: string, readonly help: string) {
    super(message)
  }
}
