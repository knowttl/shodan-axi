import { z } from 'zod'

const location = z.object({ location: z.object({ latitude: z.number().min(-90).max(90), longitude: z.number().min(-180).max(180) }) })

export class Radar {
  private readonly cells = new Set<number>()
  private plottedPoints = 0
  private ignoredPoints = 0

  add(event: unknown): void {
    const parsed = location.safeParse(event)
    if (!parsed.success) { this.ignoredPoints++; return }
    const { latitude, longitude } = parsed.data.location
    const x = Math.min(35, Math.floor((longitude + 180) / 10))
    const y = Math.min(17, Math.floor((90 - latitude) / 10))
    this.cells.add(y * 36 + x)
    this.plottedPoints++
  }

  snapshot(): { rows: string[]; plottedPoints: number; ignoredPoints: number } {
    const rows = Array.from({ length: 18 }, (_, y) => Array.from({ length: 36 }, (_, x) => this.cells.has(y * 36 + x) ? '*' : '.').join(''))
    return { rows, plottedPoints: this.plottedPoints, ignoredPoints: this.ignoredPoints }
  }
}
