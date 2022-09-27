export default function extractJwt(data: string): string | undefined {
  return data.split(' ').pop();
}
