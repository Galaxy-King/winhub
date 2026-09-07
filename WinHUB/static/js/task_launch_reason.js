// Reasons remain plain text and are submitted separately from executable payloads.
function requiredLaunchReason(id) {
    const field = document.getElementById(id);
    if (!field) return null; // Fail closed if an outdated page is missing the field.
    const value = field.value.trim();
    let message = '';
    if (!/[^\s\p{C}]/u.test(value)) message = 'A task launch reason is required.';
    else if (Array.from(value).length > 2000) message = 'The launch reason cannot exceed 2000 characters.';
    else if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/u.test(value)) message = 'Remove control characters from the launch reason.';
    field.setCustomValidity(message);
    if (message) {
        field.focus();
        field.reportValidity();
        return null;
    }
    return value;
}

function displayLaunchReason(value) {
    return value || 'Not recorded — this task predates mandatory launch reasons.';
}

let launchReasonResolver = null;
function askTaskLaunchReason(context = '') {
    if (launchReasonResolver) return Promise.resolve(null);
    const dialog = document.getElementById('taskLaunchReasonDialog');
    const field = document.getElementById('taskLaunchReasonInput');
    if (!dialog || !field) return Promise.resolve(null);
    field.value = '';
    field.setCustomValidity('');
    document.getElementById('taskLaunchReasonContext').textContent = context;
    dialog.returnValue = '';
    return new Promise(resolve => {
        launchReasonResolver = resolve;
        dialog.showModal();
        field.focus();
    });
}

document.getElementById('taskLaunchReasonForm')?.addEventListener('submit', event => {
    event.preventDefault();
    const reason = requiredLaunchReason('taskLaunchReasonInput');
    if (reason !== null) document.getElementById('taskLaunchReasonDialog').close('launch');
});
document.getElementById('taskLaunchReasonCancel')?.addEventListener('click', () => {
    document.getElementById('taskLaunchReasonDialog').close();
});
document.getElementById('taskLaunchReasonDialog')?.addEventListener('close', event => {
    const resolve = launchReasonResolver;
    launchReasonResolver = null;
    if (resolve) resolve(event.target.returnValue === 'launch' ? requiredLaunchReason('taskLaunchReasonInput') : null);
});
document.addEventListener('input', event => {
    if (event.target.matches('textarea[data-launch-reason]')) event.target.setCustomValidity('');
});
