"""A late actor response must not reach native tool execution."""
import unittest
from unittest.mock import patch

from openai.types.chat import ChatCompletion
from control_layer_v0.benchmark import run_case


class DeadlineTests(unittest.TestCase):
    def test_late_response_preserves_unknown_score_and_state(self):
        clock=[0.0]
        def late(*args,**kwargs):
            clock[0]=300.0
            return ChatCompletion.model_validate({'id':'local-test','created':0,'model':'local-test',
                'object':'chat.completion','choices':[{'index':0,'finish_reason':'stop',
                'message':{'role':'assistant','content':'<function=get_webpage>{"url":"www.informations.com"}</function>'}}]})
        with patch('control_layer_v0.benchmark.time.perf_counter',side_effect=lambda:clock[0]):
            result=run_case('slack','user_task_0','v0',create=late)
        self.assertEqual(result['status'],'error')
        self.assertIsNone(result['official_utility'])
        self.assertEqual(result['audit']['events'],[])
        self.assertEqual(result['audit']['initial_state'],result['audit']['final_state'])


if __name__=='__main__':
    unittest.main()
