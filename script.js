/* Educational pattern checks only. No network requests or cloud credentials. */
'use strict';
const bucket = 'arn:aws:s3:::student-security-lab';
const reader = { AWS: 'arn:aws:iam::123456789012:role/LabReader' };
const policyOf = (...statements) => ({ Version: '2012-10-17', Statement: statements });
const allow = (Principal, Action) => ({ Effect: 'Allow', Principal, Action, Resource: `${bucket}/*` });
const scenarios = {
  publicRead: { note: 'A wildcard principal is granted object reads. Investigate the grant and the controls outside this policy.', policy: policyOf(allow('*', 's3:GetObject')) },
  publicWrite: { note: 'Anyone is named in an object upload and deletion grant. What could happen if other controls did not restrict it?', policy: policyOf(allow('*', ['s3:PutObject', 's3:DeleteObject'])) },
  broadRole: { note: 'A named role has all S3 actions on bucket objects. Compare its permissions with the needs of a reader.', policy: policyOf(allow(reader, 's3:*')) },
  scoped: { note: 'An illustrative reader grant with an HTTPS restriction. This is a comparison example, not a guarantee of secure configuration.', policy: policyOf(allow(reader, 's3:GetObject'), { Sid: 'DenyInsecureTransport', Effect: 'Deny', Principal: '*', Action: 's3:*', Resource: [bucket, `${bucket}/*`], Condition: { Bool: { 'aws:SecureTransport': 'false', 'aws:PrincipalIsAWSService': 'false' } } }) }
};
const array = value => Array.isArray(value) ? value : [value];
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const wildcardPrincipal = p => p === '*' || (isObject(p) && array(p.AWS).includes('*'));

// Deliberately narrow structural validation, not the full policy grammar.
function analyzePolicy(policy) {
  if (!isObject(policy) || !policy.Statement) throw new Error('Provide a JSON object with a Statement object or array.');
  const statements = array(policy.Statement);
  if (!statements.length) throw new Error('Add at least one policy statement.');
  const findings = [];
  const add = (level, title, detail, next) => findings.push({ level, title, detail, next });
  let transportPattern = false;
  statements.forEach((s, i) => {
    const name = `Statement ${i + 1}`;
    if (!isObject(s) || !['Allow', 'Deny'].includes(s.Effect)) throw new Error(`${name}: Effect must be Allow or Deny.`);
    for (const key of ['Action', 'Resource']) {
      if (s[key] === undefined && s[`Not${key}`] === undefined) throw new Error(`${name}: ${key} is missing.`);
      if (s[key] !== undefined && (!array(s[key]).length || !array(s[key]).every(v => typeof v === 'string' && v.length))) throw new Error(`${name}: ${key} must be a string or nonempty array of strings.`);
    }
    if (s.Principal === undefined && s.NotPrincipal === undefined) throw new Error(`${name}: a bucket policy needs Principal or NotPrincipal.`);
    if (s.Principal !== undefined && !(typeof s.Principal === 'string' || isObject(s.Principal))) throw new Error(`${name}: Principal must be a string or object.`);
    if (s.Condition !== undefined && !isObject(s.Condition)) throw new Error(`${name}: Condition must be an object.`);
    if (s.NotAction !== undefined || s.NotResource !== undefined || s.NotPrincipal !== undefined) add('review', `${name}: exclusion syntax needs manual review`, 'NotAction, NotResource, and NotPrincipal are outside the supported checks.', 'Use your cloud provider\'s policy validation and review the complete authorization context.');
    const actions = array(s.Action ?? []).map(v => v.toLowerCase());
    const resources = array(s.Resource ?? []);
    if (s.Effect === 'Allow') {
      if (wildcardPrincipal(s.Principal)) add('high', `${name}: wildcard principal in an Allow`, 'This grant includes a wildcard principal. Conditions, explicit denies, and Block Public Access may restrict its effect; this is not proof of public exposure.', 'Replace the grant with the intended principal and inspect all applicable controls.');
      if (actions.some(a => a.includes('*') || a.includes('?'))) add('review', `${name}: wildcard action permissions`, 'The action list uses a wildcard. Its scope may exceed what the workload needs.', 'Replace wildcard actions with the smallest required action set.');
      if (wildcardPrincipal(s.Principal) && actions.some(a => /^(s3:(put|delete)|s3:\*|\*$)/.test(a))) add('high', `${name}: possible public modification grant`, 'A wildcard principal is paired with write/delete actions or all actions. This could permit modification if the complete authorization context allows it.', 'Remove unintended modification permissions and check account and bucket public access controls.');
      if (resources.includes('*')) add('review', `${name}: wildcard resource`, 'The resource scope is not limited to a specific ARN. This checker does not validate resource/action compatibility.', 'Use the intended bucket or object ARN and validate the policy with your cloud provider\'s tools before use.');
    }
    const bool = s.Condition?.Bool;
    if (s.Effect === 'Deny' && wildcardPrincipal(s.Principal) && actions.some(a => a === '*' || a === 's3:*') && isObject(bool) && [false, 'false'].includes(bool['aws:SecureTransport'])) {
      transportPattern = true;
      add('info', `${name}: HTTPS-deny pattern detected`, 'A deny-all-S3-actions pattern checks for insecure transport. Resource coverage, other conditions, and service-principal exceptions still require review.', 'Confirm that the intended bucket and objects are covered and required cloud services can operate.');
    }
    if (s.Condition && !(s.Effect === 'Deny' && isObject(bool) && [false, 'false'].includes(bool['aws:SecureTransport']))) add('review', `${name}: conditions need contextual review`, 'This checker does not evaluate condition logic or determine whether conditions limit a wildcard principal.', 'Inspect each condition key, operator, and value using the provider\'s documentation.');
  });
  if (!transportPattern) add('review', 'No supported HTTPS-deny pattern found', 'This policy does not match the narrow transport restriction pattern checked by the lab. This does not mean the data is unencrypted or HTTP is allowed.', 'Review enforcement of encrypted connections separately, including policies outside this input.');
  add('info', 'Verify the rest of the configuration', 'Policy JSON alone does not reveal encryption at rest, Block Public Access, ACLs, IAM identity policies, or actual access.', 'For a future hands-on lab, inspect those controls and test authorized and unauthorized requests.');
  return findings;
}

// Export the pure checker for local tests without requiring a browser.
if (typeof module !== 'undefined' && module.exports) module.exports = { analyzePolicy, scenarios };
if (typeof document !== 'undefined') {
  const $ = id => document.getElementById(id);
  let report = '';
  const invalidate = () => {
    report = ''; $('download').disabled = true; $('findings').replaceChildren();
    $('result-state').textContent = 'Not analyzed';
    $('result-summary').textContent = 'Analyze the current policy to see findings and next steps.';
    $('editor-status').textContent = '';
  };
  function loadScenario() {
    const selected = scenarios[$('scenario').value];
    $('policy').value = JSON.stringify(selected.policy, null, 2);
    $('scenario-note').textContent = selected.note;
    invalidate();
  }
  function parseInput() {
    if (!$('policy').value.trim()) throw new Error('Enter a policy or select an example first.');
    try { return JSON.parse($('policy').value); } catch { throw new Error('Invalid JSON. Check quotation marks, commas, and matching braces.'); }
  }
  $('analyze').addEventListener('click', () => {
    invalidate();
    try {
      const findings = analyzePolicy(parseInput());
      const count = findings.filter(f => f.level !== 'info').length;
      $('result-state').textContent = `${count} review item${count === 1 ? '' : 's'}`;
      $('result-summary').textContent = count ? 'These patterns need investigation. They do not establish effective access in a real environment.' : 'No risk patterns flagged by these limited checks. This is not a security certification.';
      findings.forEach(f => {
        const card = document.createElement('article'); card.className = `finding ${f.level}`;
        const label = document.createElement('span'); label.className = 'severity'; label.textContent = { high: 'HIGH PRIORITY REVIEW', review: 'REVIEW', info: 'OBSERVATION' }[f.level];
        const title = document.createElement('h4'); title.textContent = f.title;
        const detail = document.createElement('p'); detail.textContent = f.detail;
        const next = document.createElement('p'); next.className = 'next'; next.textContent = `Next step: ${f.next}`;
        card.append(label, title, detail, next); $('findings').append(card);
      });
      report = ['Cloud Storage Security Lab — local policy review', `Created: ${new Date().toISOString()}`, 'Educational pattern analysis only. No cloud resources inspected. Findings do not prove effective access.', '', ...findings.map(f => `[${f.level.toUpperCase()}] ${f.title}\n${f.detail}\nNext step: ${f.next}\n`), 'INPUT POLICY', $('policy').value].join('\n');
      $('download').disabled = false; $('editor-status').textContent = 'Review complete. Your policy was processed only in this browser.';
    } catch (error) { $('editor-status').textContent = error.message; $('result-state').textContent = 'Check input'; }
  });
  $('format').addEventListener('click', () => {
    try { const value = parseInput(); $('policy').value = JSON.stringify(value, null, 2); invalidate(); $('editor-status').textContent = 'JSON formatted. Analyze to refresh the review.'; }
    catch (error) { $('editor-status').textContent = error.message; }
  });
  $('download').addEventListener('click', () => {
    if (!report) return;
    const url = URL.createObjectURL(new Blob([report], { type: 'text/plain;charset=utf-8' }));
    const link = document.createElement('a'); link.href = url; link.download = 'cloud-storage-policy-review.txt';
    document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  $('scenario').addEventListener('change', loadScenario);
  $('reset').addEventListener('click', loadScenario);
  $('policy').addEventListener('input', invalidate);
  loadScenario();
}
