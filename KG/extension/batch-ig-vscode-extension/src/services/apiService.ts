import * as vscode from 'vscode';
import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';
import { Job, Step, GapInfo } from '../models/types';

export interface JavaMethodInfo {
    methodFqn: string;
    methodName?: string;
    javaLineCount?: number;
    sourceCode?: string;
    filePath?: string;
    classFqn?: string;
    gitBranchName?: string;
    gitRepoName?: string;
}

export interface Repository {
    name: string;
    repoName?: string;
    repoUrl?: string;
    branchName?: string;
    path?: string;
    repoType?: string;
}

/**
 * Thin HTTP client that replaces direct Neo4j access.
 * All graph queries go through the Batch-IG-Extension-APIs FastAPI service.
 */
export class ApiService {

    private getBaseUrl(): string {
        const config = vscode.workspace.getConfiguration('batchIg');
        console.log('Using API base URL:', config.get<string>('apiUrl'));
        return config.get<string>('apiUrl', 'http://localhost:8000');
    }

    private request<T>(path: string): Promise<T> {
        const baseUrl = this.getBaseUrl();
        const urlString = `${baseUrl}${path}`;

        return new Promise((resolve, reject) => {
            let url: URL;
            try {
                url = new URL(urlString);
            } catch {
                return reject(new Error(`Invalid API URL: ${urlString}`));
            }

            const transport = url.protocol === 'https:' ? https : http;

            const req = transport.get(urlString, (res) => {
                let body = '';
                res.on('data', (chunk: Buffer) => { body += chunk.toString(); });
                res.on('end', () => {
                    if (res.statusCode === 404) {
                        // Treat 404 as a null result (caller decides how to handle)
                        resolve(null as unknown as T);
                        return;
                    }
                    if (res.statusCode && res.statusCode >= 400) {
                        try {
                            const err = JSON.parse(body);
                            reject(new Error(err.detail || `HTTP ${res.statusCode}`));
                        } catch {
                            reject(new Error(`HTTP ${res.statusCode}: ${body}`));
                        }
                        return;
                    }
                    try {
                        resolve(JSON.parse(body) as T);
                    } catch {
                        reject(new Error('Invalid JSON received from API'));
                    }
                });
            });

            req.on('error', (err: Error) => {
                reject(new Error(
                    `Cannot reach API at ${baseUrl}. ` +
                    `Start Batch-IG-Extension-APIs and verify "batchIg.apiUrl". ` +
                    `(${err.message})`
                ));
            });

            req.setTimeout(10_000, () => {
                req.destroy();
                reject(new Error(`API request timed out: ${urlString}`));
            });
        });
    }

    async testConnection(): Promise<boolean> {
        try {
            await this.request('/api/v1/health');
            return true;
        } catch {
            return false;
        }
    }

    async getAllJobs(): Promise<Job[]> {
        return this.request<Job[]>('/api/v1/jobs');
    }

    async getStepsForJob(jobName: string): Promise<Step[]> {
        const encoded = encodeURIComponent(jobName);
        return this.request<Step[]>(`/api/v1/jobs/${encoded}/steps`);
    }

    async getGapsForStep(stepName: string): Promise<{ db: GapInfo[]; procedure: GapInfo[]; shell: GapInfo[] }> {
        const encoded = encodeURIComponent(stepName);
        return this.request(`/api/v1/steps/${encoded}/gaps`);
    }

    async getJavaFileForMethod(methodFqn: string): Promise<JavaMethodInfo | null> {
        const encoded = encodeURIComponent(methodFqn);
        return this.request<JavaMethodInfo | null>(
            `/api/v1/methods/java-file?fqn=${encoded}`
        );
    }

    async getRepositories(): Promise<Repository[]> {
        return this.request<Repository[]>('/api/v1/repositories');
    }

    /** No-op — connection lifecycle is managed by the API server. */
    async close(): Promise<void> {
        // Nothing to do
    }
}
