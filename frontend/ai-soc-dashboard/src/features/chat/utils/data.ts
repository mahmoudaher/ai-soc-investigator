import type { Conversation } from './types';

export const initialConversations: Conversation[] = [
  {
    id: 'case-triage',
    name: 'Triage Agent',
    title: 'Windows Failed Logon Case',
    status: 'online',
    unread: 2,
    initials: 'TA',
    messages: [
      {
        id: 'triage-1',
        sender: 'contact',
        author: 'Triage Agent',
        text: 'I normalized the Wazuh alert and identified a failed Administrator logon from 192.168.56.10 against WIN11-LAB.',
        timestamp: '10:02'
      },
      {
        id: 'triage-2',
        sender: 'user',
        author: 'You',
        text: 'Classify severity and tell me what I should inspect first during the presentation.',
        timestamp: '10:05'
      },
      {
        id: 'triage-3',
        sender: 'contact',
        author: 'Triage Agent',
        text: 'Recommended severity is high. Lead with source IP, target account, process name, and whether repeated failures exist in nearby events.',
        timestamp: '10:08'
      }
    ],
    quickReplies: [
      'Show the top entities.',
      'Draft a short case summary.',
      'What is the next evidence step?'
    ],
    autoReplies: [
      'Top entities are WIN11-LAB, Administrator, 192.168.56.10, and svchost.exe.',
      'This case shows a suspicious Windows authentication failure targeting Administrator, requiring source validation and timeline review.',
      'Collect neighboring Windows EventChannel logs and compare failed attempts by account, host, and source IP.'
    ]
  },
  {
    id: 'evidence-review',
    name: 'Evidence Agent',
    title: 'Evidence Collection Review',
    status: 'online',
    unread: 0,
    initials: 'EA',
    messages: [
      {
        id: 'evidence-1',
        sender: 'user',
        author: 'You',
        text: 'What evidence should be attached to the case before I show the final view?',
        timestamp: '09:15'
      },
      {
        id: 'evidence-2',
        sender: 'contact',
        author: 'Evidence Agent',
        text: 'Attach the normalized alert, extracted entities, timeline events, and any corroborating logs around the same timestamp.',
        timestamp: '09:18'
      },
      {
        id: 'evidence-3',
        sender: 'user',
        author: 'You',
        text: 'Can we explain why this is not just a random failed login?',
        timestamp: '09:22'
      },
      {
        id: 'evidence-4',
        sender: 'contact',
        author: 'Evidence Agent',
        text: 'Yes. Use target account sensitivity, source context, recurrence, process metadata, and whether the host has related security events.',
        timestamp: '09:25'
      }
    ],
    quickReplies: [
      'Summarize supporting evidence.',
      'List missing evidence.',
      'Prepare analyst notes.'
    ],
    autoReplies: [
      'Supporting evidence includes the Wazuh rule, raw Windows event fields, source IP, target user, and process name.',
      'Missing evidence may include neighboring event IDs, successful logons after failure, and endpoint process telemetry.',
      'Analyst note: validate whether the source IP is expected admin infrastructure before escalation.'
    ]
  },
  {
    id: 'final-report',
    name: 'Reporter Agent',
    title: 'Final Case Narrative',
    status: 'offline',
    unread: 1,
    initials: 'RA',
    messages: [
      {
        id: 'report-1',
        sender: 'contact',
        author: 'Reporter Agent',
        text: 'I can turn the case file into a presentation-ready summary with severity, affected assets, timeline, and response recommendations.',
        timestamp: 'Yesterday'
      },
      {
        id: 'report-2',
        sender: 'user',
        author: 'You',
        text: 'Make it concise. I need to explain the flow from alert ingestion to final recommendation.',
        timestamp: 'Yesterday'
      }
    ],
    quickReplies: [
      'Draft the final summary.',
      'Make it more technical.',
      'Create response actions.'
    ],
    autoReplies: [
      'Final summary: Wazuh detected suspicious authentication activity, the workflow normalized it into a case, extracted observables, collected evidence, and prepared recommendations.',
      'Technical angle: focus on CaseFile state transitions, checkpoint persistence, and agent-owned fields.',
      'Response actions: validate source, check for successful follow-up logons, review endpoint logs, and monitor the target account.'
    ]
  }
];
