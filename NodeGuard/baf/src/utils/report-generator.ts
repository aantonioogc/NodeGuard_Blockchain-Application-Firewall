// src/utils/report-generator.ts
// ajgc: generador de informes de seguridad NodeGuard

import { Buffer } from 'buffer';

interface ReportData {
  metrics: {
    totalRequests: number;
    blockedRequests: number;
    allowedRequests: number;
    blockRate: number;
  };
  topAttackers: Array<{ip: string, score: number, attacks: number}>;
  attackReasons: {[reason: string]: number};
  period: {startDate: string, endDate: string};
  includeDetails: boolean;
  generatedAt: string;
  generatedBy: string;
}

/**
 * ajgc: generar informe de seguridad en HTML
 * TODO: en producción usar puppeteer para PDF real
 */
export async function generateSecurityReport(data: ReportData): Promise<Buffer> {
  const htmlContent = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <title>Informe de Seguridad NodeGuard</title>
      <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { text-align: center; margin-bottom: 40px; }
        .section { margin-bottom: 30px; }
        .metrics { display: flex; justify-content: space-around; }
        .metric { text-align: center; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>NodeGuard - Informe de Seguridad</h1>
        <p>Generado: ${new Date(data.generatedAt).toLocaleString()}</p>
        <p>Periodo: ${new Date(data.period.startDate).toLocaleDateString()} - ${new Date(data.period.endDate).toLocaleDateString()}</p>
      </div>
      
      <div class="section">
        <h2>Resumen de Métricas</h2>
        <div class="metrics">
          <div class="metric">
            <h3>${data.metrics.totalRequests.toLocaleString()}</h3>
            <p>Peticiones Totales</p>
          </div>
          <div class="metric">
            <h3>${data.metrics.blockedRequests.toLocaleString()}</h3>
            <p>Ataques Bloqueados</p>
          </div>
          <div class="metric">
            <h3>${data.metrics.allowedRequests.toLocaleString()}</h3>
            <p>Peticiones Permitidas</p>
          </div>
          <div class="metric">
            <h3>${data.metrics.blockRate.toFixed(2)}%</h3>
            <p>Tasa de Bloqueo</p>
          </div>
        </div>
      </div>
      
      <div class="section">
        <h2>Principales Atacantes</h2>
        <table>
          <thead>
            <tr><th>Dirección IP</th><th>Puntuación</th><th>Nº Ataques</th></tr>
          </thead>
          <tbody>
            ${data.topAttackers.map(attacker => 
              `<tr><td>${attacker.ip}</td><td>${attacker.score}</td><td>${attacker.attacks}</td></tr>`
            ).join('')}
          </tbody>
        </table>
      </div>
      
      <div class="section">
        <h2>Distribución de Ataques</h2>
        <table>
          <thead>
            <tr><th>Tipo de Ataque</th><th>Cantidad</th><th>Porcentaje</th></tr>
          </thead>
          <tbody>
            ${Object.entries(data.attackReasons).map(([reason, count]) => {
              const total = Object.values(data.attackReasons).reduce((a, b) => a + b, 0);
              const percentage = total > 0 ? ((count / total) * 100).toFixed(1) : 0;
              return `<tr><td>${reason}</td><td>${count}</td><td>${percentage}%</td></tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>
      
      <div class="section">
        <p><em>Informe generado por NodeGuard BAF v2.0 - Desarrollado por ajgc</em></p>
      </div>
    </body>
    </html>
  `;
  
  // ajgc: por ahora devolvemos HTML, en producción convertir a PDF
  return Buffer.from(htmlContent, 'utf8');
}
