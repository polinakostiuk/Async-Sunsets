from django.contrib import admin
from .models import AttackScenario, SimulationLog


@admin.register(AttackScenario)
class AttackScenarioAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'title',
        'vulnerability_type',
        'severity',
        'defense_active',
        'is_published',
        'created_by',
        'created_at',
    )
    list_filter = ('vulnerability_type', 'severity', 'is_published', 'defense_active')
    search_fields = ('title', 'description', 'attack_vector')
    readonly_fields = ('created_at', 'updated_at')


@admin.register(SimulationLog)
class SimulationLogAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'scenario',
        'executed_by',
        'defense_enabled',
        'status',
        'created_at',
    )
    list_filter = ('status', 'defense_enabled', 'created_at')
    search_fields = ('scenario__title', 'executed_by__username', 'result_details')
    readonly_fields = ('created_at',)
