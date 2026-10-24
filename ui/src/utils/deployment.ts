// SPDX-License-Identifier: AGPL-3.0-only
import { deploymentPath, normalizeBasePath, stripDeploymentBase } from './deploymentPath'

export const APP_BASE_PATH = normalizeBasePath(import.meta.env.BASE_URL || '/')
/** Vite-owned outer prefix only; internal API/protocol route names stay unchanged. */
export const appPath = (path: string): string => deploymentPath(path, APP_BASE_PATH)
export const appOrigin = (origin: string): string => `${origin.replace(/\/+$/, '')}${APP_BASE_PATH.slice(0, -1)}`
export const appRoutePath = (pathname: string): string => stripDeploymentBase(pathname, APP_BASE_PATH) ?? ''
