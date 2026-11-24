from django.db import models
from django.contrib.auth.models import User


class Vulnerability(models.Model):
    CATEGORY_CHOICES = [
        ('SQLI', 'SQL Injection'),
        ('XSS', 'Cross-Site Scripting (XSS)'),
        ('BAC', 'Broken Access Control'),
    ]

    title = models.CharField(max_length=200)
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES)
    description = models.TextField()
    remediation = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} ({self.category})"


class AttackScenario(models.Model):
    vulnerability = models.ForeignKey(
        Vulnerability, on_delete=models.CASCADE, related_name='scenarios'
    )
    name = models.CharField(max_length=200)
    vulnerable_code_snippet = models.TextField()
    secure_code_snippet = models.TextField()
    payload_example = models.TextField()
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.name


class SimulationLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    scenario = models.ForeignKey(AttackScenario, on_delete=models.CASCADE)
    is_secure_mode = models.BooleanField(default=False)
    is_blocked = models.BooleanField(default=False)
    executed_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        status = "Blocked" if self.is_blocked else "Exploited"
        return f"{self.scenario.name} - {status}"