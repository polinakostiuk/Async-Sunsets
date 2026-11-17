from rest_framework import serializers
from .models import AttackScenario, SimulationLog


class AttackScenarioSerializer(serializers.ModelSerializer):
    created_by_username = serializers.ReadOnlyField(source='created_by.username')

    class Meta:
        model = AttackScenario
        fields = [
            'id',
            'title',
            'description',
            'vulnerability_type',
            'severity',
            'attack_vector',
            'defense_mechanism',
            'defense_active',
            'is_published',
            'created_by',
            'created_by_username',
            'created_at',
            'updated_at',
        ]
        read_only_fields = ['id', 'created_by', 'created_by_username', 'created_at', 'updated_at']

    def validate_title(self, value):
        cleaned_value = value.strip()
        if len(cleaned_value) < 5:
            raise serializers.ValidationError(
                "Назва сценарію повинна містити щонайменше 5 символів."
            )
        return cleaned_value

    def validate(self, attrs):
        request = self.context.get('request')
        user = request.user if request else None

        # Якщо звичайний користувач намагається встановити is_published=True
        is_published = attrs.get('is_published')
        if is_published is True:
            if not user or not user.is_staff:
                raise serializers.ValidationError({
                    'is_published': "Лише адміністратор має право публікувати сценарії."
                })

        return attrs


class SimulationRequestSerializer(serializers.Serializer):
    payload = serializers.CharField(
        max_length=1000,
        required=True,
        trim_whitespace=False,
        help_text="Корисне навантаження атаки (наприклад, SQL ін'єкція або XSS скрипт)"
    )
    defense_enabled = serializers.BooleanField(
        required=False,
        default=True,
        help_text="Чи активовано захисний бар'єр під час виконання симуляції"
    )

    def validate_payload(self, value):
        cleaned = value.strip()
        if not cleaned:
            raise serializers.ValidationError("Корисне навантаження (payload) не може бути порожнім.")
        return cleaned


class SimulationResponseSerializer(serializers.Serializer):
    simulation_id = serializers.IntegerField(help_text="Унікальний ідентифікатор запущеної симуляції")
    scenario_id = serializers.IntegerField(help_text="Ідентифікатор сценарію атаки")
    scenario_title = serializers.CharField(help_text="Назва сценарію")
    vulnerability_type = serializers.CharField(help_text="Тип вразливості")
    defense_enabled = serializers.BooleanField(help_text="Статус захисного бар'єру")
    is_blocked = serializers.BooleanField(help_text="Чи була атака успішно нейтралізована")
    status = serializers.ChoiceField(
        choices=SimulationLog.SimulationStatus.choices,
        help_text="Статус симуляції"
    )
    message = serializers.CharField(help_text="Повідомлення з результатом виконання атаки")
    created_at = serializers.DateTimeField(help_text="Мітка часу виконання")


class SimulationLogSerializer(serializers.ModelSerializer):
    executed_by_username = serializers.ReadOnlyField(source='executed_by.username')
    scenario_title = serializers.ReadOnlyField(source='scenario.title')

    class Meta:
        model = SimulationLog
        fields = [
            'id',
            'scenario',
            'scenario_title',
            'executed_by',
            'executed_by_username',
            'payload',
            'defense_enabled',
            'status',
            'result_details',
            'created_at',
        ]
        read_only_fields = fields
