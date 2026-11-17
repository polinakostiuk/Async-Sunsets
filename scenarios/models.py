from django.contrib.auth.models import User
from django.db import models


class AttackScenario(models.Model):
    """
    Модель сценарію кібератаки для інтерактивної пісочниці SecureFlow.
    """

    class VulnerabilityType(models.TextChoices):
        SQL_INJECTION = 'SQLI', 'SQL Injection'
        CROSS_SITE_SCRIPTING = 'XSS', 'Cross-Site Scripting'
        BROKEN_ACCESS_CONTROL = 'BAC', 'Broken Access Control'
        CSRF = 'CSRF', 'Cross-Site Request Forgery'
        SSRF = 'SSRF', 'Server-Side Request Forgery'

    class SeverityLevel(models.TextChoices):
        LOW = 'LOW', 'Низький'
        MEDIUM = 'MEDIUM', 'Середній'
        HIGH = 'HIGH', 'Високий'
        CRITICAL = 'CRITICAL', 'Критичний'

    title = models.CharField(
        max_length=200,
        verbose_name="Назва сценарію",
        help_text="Коротка та інформативна назва вразливості або ланцюга атаки"
    )
    description = models.TextField(
        verbose_name="Опис сценарію",
        help_text="Детальний опис вектора вразливості та контексту застосунку"
    )
    vulnerability_type = models.CharField(
        max_length=10,
        choices=VulnerabilityType.choices,
        default=VulnerabilityType.SQL_INJECTION,
        verbose_name="Тип вразливості"
    )
    severity = models.CharField(
        max_length=10,
        choices=SeverityLevel.choices,
        default=SeverityLevel.MEDIUM,
        verbose_name="Рівень критичності"
    )
    attack_vector = models.TextField(
        verbose_name="Вектор атаки",
        help_text="Опис технічних кроків та корисного навантаження (payload)"
    )
    defense_mechanism = models.TextField(
        verbose_name="Механізм захисту",
        help_text="Опис захисного бар'єру (параметризація, санітизація, RBAC тощо)"
    )
    defense_active = models.BooleanField(
        default=True,
        verbose_name="Захисний бар'єр активний",
        help_text="Чи активовано захисний механізм за замовчуванням"
    )
    is_published = models.BooleanField(
        default=False,
        verbose_name="Опубліковано",
        help_text="Чи доступний сценарій для публічного перегляду гостями"
    )
    created_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='created_scenarios',
        verbose_name="Автор"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Створено"
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name="Оновлено"
    )

    class Meta:
        verbose_name = "Сценарій атаки"
        verbose_name_plural = "Сценарії атак"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} [{self.get_vulnerability_type_display()}] ({self.severity})"


class SimulationLog(models.Model):
    """
    Модель журналу симуляцій кібератак.
    Фіксує кожну спробу запуску атаки в пісочниці.
    """

    class SimulationStatus(models.TextChoices):
        MITIGATED = 'MITIGATED', 'Заблоковано захистом'
        BREACHED = 'BREACHED', 'Успішний прорив'
        ERROR = 'ERROR', 'Помилка симуляції'

    scenario = models.ForeignKey(
        AttackScenario,
        on_delete=models.CASCADE,
        related_name='simulations',
        verbose_name="Сценарій"
    )
    executed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='executed_simulations',
        verbose_name="Користувач"
    )
    payload = models.TextField(
        verbose_name="Корисне навантаження"
    )
    defense_enabled = models.BooleanField(
        default=True,
        verbose_name="Захист увімкнено"
    )
    status = models.CharField(
        max_length=20,
        choices=SimulationStatus.choices,
        default=SimulationStatus.MITIGATED,
        verbose_name="Статус результату"
    )
    result_details = models.TextField(
        verbose_name="Деталі результату"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="Час запуску"
    )

    class Meta:
        verbose_name = "Журнал симуляції"
        verbose_name_plural = "Журнали симуляцій"
        ordering = ['-created_at']

    def __str__(self):
        return f"Симуляція #{self.pk} ({self.scenario.title}) - {self.status}"
