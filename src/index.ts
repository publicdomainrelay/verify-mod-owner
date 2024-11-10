import * as core from '@actions/core';
import * as child_process from 'child_process';
import * as fs from 'fs';
import * as openpgp from 'openpgp';
import * as sshpk from 'sshpk';
import * as tmp from 'tmp';

interface PublicKeys {
  [identifier: string]: {
    pgpKeys?: openpgp.PublicKey[];
    sshKeys?: sshpk.Key[];
  };
}

async function run() {
  try {
    // Get inputs
    const baseBranch = core.getInput('base_branch') || 'main';
    const filePath = core.getInput('file_path');
    const publicKeyFilesInput = core.getMultilineInput('public_key_files');
    const commitsInput = core.getInput('commits');

    let commitShas: string[] = [];

    if (commitsInput) {
      // Parse commits from input
      commitShas = JSON.parse(commitsInput);
    } else {
      // Compute commits that differ from baseBranch
      const mergeBase = child_process
        .execSync(`git merge-base HEAD ${baseBranch}`)
        .toString()
        .trim();

      let diffCommand = `git rev-list ${mergeBase}..HEAD`;
      if (filePath) {
        diffCommand = `git log --pretty=format:"%H" ${mergeBase}..HEAD -- ${filePath}`;
      }
      const commitList = child_process.execSync(diffCommand).toString().trim();
      commitShas = commitList.split('\n').filter((sha) => sha);
    }

    // Load public keys
    const publicKeys: PublicKeys = {};

    for (const keyFile of publicKeyFilesInput) {
      const keyData = fs.readFileSync(keyFile, 'utf8');

      if (keyData.includes('BEGIN PGP PUBLIC KEY BLOCK')) {
        // PGP Key
        const key = await openpgp.readKey({ armoredKey: keyData });
        const userIds = key.getUserIDs(); // Array of user IDs (emails)

        userIds.forEach((email) => {
          if (!publicKeys[email]) publicKeys[email] = {};
          if (!publicKeys[email].pgpKeys) publicKeys[email].pgpKeys = [];
          publicKeys[email].pgpKeys!.push(key);
        });
      } else {
        // SSH Key
        const key = sshpk.parseKey(keyData, 'ssh');
        const comment = key.comment || 'unknown';

        if (!publicKeys[comment]) publicKeys[comment] = {};
        if (!publicKeys[comment].sshKeys) publicKeys[comment].sshKeys = [];
        publicKeys[comment].sshKeys!.push(key);
      }
    }

    // Verify each commit
    let allVerified = true;

    for (const sha of commitShas) {
      // Get commit data
      const commitData = child_process.execSync(`git cat-file commit ${sha}`).toString();

      // Parse commit object
      const { signedData, signature, sigType } = parseCommitObject(commitData);

      if (sigType === 'gpgsig') {
        // Verify GPG signature
        const verified = await verifyGpgSignature(signedData, signature, publicKeys);
        if (verified) {
          core.info(`Commit ${sha} GPG signature verified.`);
        } else {
          core.error(`Commit ${sha} GPG signature verification failed.`);
          allVerified = false;
        }
      } else if (sigType === 'sshsig') {
        // Verify SSH signature
        const verified = await verifySshSignature(signedData, signature, publicKeys);
        if (verified) {
          core.info(`Commit ${sha} SSH signature verified.`);
        } else {
          core.error(`Commit ${sha} SSH signature verification failed.`);
          allVerified = false;
        }
      } else {
        core.error(`Commit ${sha} is not signed.`);
        allVerified = false;
      }
    }

    if (!allVerified) {
      core.setFailed('One or more commits failed verification.');
    }
  } catch (error: any) {
    core.setFailed(`Action failed with error: ${error.message}`);
  }
}

// Function to parse the commit object and extract signed data and signature
function parseCommitObject(commitData: string): { signedData: string; signature: string; sigType: string } {
  const lines = commitData.split('\n');
  let signatureLines: string[] = [];
  let signedDataLines: string[] = [];
  let sigType = ''; // 'gpgsig' or 'sshsig'
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (line.startsWith('gpgsig')) {
      sigType = 'gpgsig';
      signedDataLines.push(line);
      if (line.length > 6) signatureLines.push(line.substring(7));
      i++;

      while (i < lines.length && lines[i].startsWith(' ')) {
        const sigLine = lines[i];
        signatureLines.push(sigLine.substring(1)); // Remove leading space
        i++;
      }

      // Replace the signature in the signed data with a blank line
      signedDataLines.push('');
    } else if (line.startsWith('sshsig')) {
      sigType = 'sshsig';
      signedDataLines.push(line);
      if (line.length > 6) signatureLines.push(line.substring(7));
      i++;

      while (i < lines.length && lines[i].startsWith(' ')) {
        const sigLine = lines[i];
        signatureLines.push(sigLine.substring(1)); // Remove leading space
        i++;
      }

      // Replace the signature in the signed data with a blank line
      signedDataLines.push('');
    } else {
      signedDataLines.push(line);
      i++;
    }
  }

  const signedData = signedDataLines.join('\n');
  const signature = signatureLines.join('\n');

  return { signedData, signature, sigType };
}

// Function to verify GPG signature
async function verifyGpgSignature(
  signedData: string,
  signature: string,
  publicKeys: PublicKeys
): Promise<boolean> {
  try {
    const message = await openpgp.createMessage({ text: signedData });
    const signatureObj = await openpgp.readSignature({ armoredSignature: signature });

    // Extract key IDs from the signature
    const keyIDs = signatureObj.getSigningKeyIDs();
    const keyID = keyIDs[0];
    const keyIdHex = keyID.toHex().toUpperCase();

    // Attempt to find the public key that matches the key ID
    let publicKey: openpgp.PublicKey | null = null;
    for (const email in publicKeys) {
      const pgpKeys = publicKeys[email].pgpKeys;
      if (pgpKeys) {
        for (const key of pgpKeys) {
          const keyIds = key.getKeyIDs().map((k) => k.toHex().toUpperCase());
          if (keyIds.includes(keyIdHex)) {
            publicKey = key;
            break;
          }
        }
      }
      if (publicKey) break;
    }

    if (!publicKey) {
      core.error(`No public key found for key ID ${keyIdHex}`);
      return false;
    }

    const verificationResult = await openpgp.verify({
      message,
      signature: signatureObj,
      verificationKeys: publicKey,
    });

    const { verified } = verificationResult.signatures[0];
    await verified; // Throws if signature is invalid
    return true;
  } catch (error: any) {
    core.error(`Error verifying GPG signature: ${error.message}`);
    return false;
  }
}

// Function to verify SSH signature
async function verifySshSignature(
  signedData: string,
  signature: string,
  publicKeys: PublicKeys
): Promise<boolean> {
  try {
    const signedDataFile = tmp.fileSync();
    fs.writeFileSync(signedDataFile.name, signedData);

    const signatureFile = tmp.fileSync();
    fs.writeFileSync(signatureFile.name, signature);

    let verified = false;

    // Iterate over SSH keys
    for (const comment in publicKeys) {
      const sshKeys = publicKeys[comment].sshKeys;
      if (sshKeys) {
        for (const sshKey of sshKeys) {
          // Save the public key to a temporary file
          const publicKeyFile = tmp.fileSync();
          fs.writeFileSync(publicKeyFile.name, sshKey.toString('ssh'));

          // Use ssh-keygen to verify the signature
          try {
            child_process.execSync(
              `ssh-keygen -Y verify -n git -f "${publicKeyFile.name}" -s "${signatureFile.name}" < "${signedDataFile.name}"`,
              { stdio: 'ignore' }
            );
            verified = true;
            publicKeyFile.removeCallback();
            break;
          } catch (error) {
            // Verification failed with this key, try the next
          } finally {
            publicKeyFile.removeCallback();
          }
        }
      }
      if (verified) break;
    }

    // Clean up temporary files
    signedDataFile.removeCallback();
    signatureFile.removeCallback();

    return verified;
  } catch (error: any) {
    core.error(`Error verifying SSH signature: ${error.message}`);
    return false;
  }
}

// Run the action
run();
