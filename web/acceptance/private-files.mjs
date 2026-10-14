// SPDX-License-Identifier: Apache-2.0

import { constants } from "node:fs";
import { open, mkdir, lstat, rename, unlink } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { randomUUID } from "node:crypto";

export async function privateDirectory(path) {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const stat = await lstat(path);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    stat.mode & 0o077 ||
    stat.uid !== process.getuid()
  ) {
    throw new Error("private_owned_directory_required");
  }
}

export async function readPrivateJSON(path) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await file.stat();
    if (
      !stat.isFile() ||
      stat.size > 1024 * 1024 ||
      stat.mode & 0o077 ||
      stat.uid !== process.getuid()
    ) {
      throw new Error("private_owned_bounded_json_required");
    }
    return JSON.parse(await file.readFile("utf8"));
  } finally {
    await file.close();
  }
}

export async function writePrivate(path, value) {
  path = resolve(path);
  await privateDirectory(dirname(path));
  const temporary = `${path}.${randomUUID()}.tmp`;
  const file = await open(
    temporary,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
    0o600,
  );
  try {
    await file.writeFile(value);
    await file.sync();
  } catch (error) {
    await unlink(temporary);
    throw error;
  } finally {
    await file.close();
  }
  await rename(temporary, path);
}

export async function writePrivateJSON(path, value) {
  await writePrivate(path, JSON.stringify(value, null, 2) + "\n");
}
