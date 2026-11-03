// @ts-ignore
const unsafe: any = { field: 1 }
export const assignment: number = unsafe
export const field = unsafe.field as number
export const called = unsafe()
export function returns(): number { return unsafe }
