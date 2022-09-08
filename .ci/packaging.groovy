#!/usr/bin/env groovy
@Library('apm@current') _

pipeline {
  agent none
  environment {
    REPO = 'fleet-server'
    BASE_DIR = "src/github.com/elastic/${env.REPO}"
    SLACK_CHANNEL = '#elastic-agent-control-plane'
    NOTIFY_TO = 'fleet-server+build-package@elastic.co'
    JOB_GCS_BUCKET = credentials('gcs-bucket')
    JOB_GCS_CREDENTIALS = 'fleet-ci-gcs-plugin'
    DOCKER_SECRET = 'secret/observability-team/ci/docker-registry/prod'
    DOCKER_REGISTRY = 'docker.elastic.co'
    DRA_OUTPUT = 'release-manager.out'
    COMMIT = "${params?.COMMIT}"
    JOB_GIT_CREDENTIALS = "f6c7695a-671e-4f4f-a331-acdce44ff9ba"
  }
  options {
    timeout(time: 2, unit: 'HOURS')
    buildDiscarder(logRotator(numToKeepStr: '100', artifactNumToKeepStr: '30', daysToKeepStr: '30'))
    timestamps()
    ansiColor('xterm')
    disableResume()
    durabilityHint('PERFORMANCE_OPTIMIZED')
    rateLimitBuilds(throttle: [count: 60, durationName: 'hour', userBoost: true])
    quietPeriod(10)
  }
  parameters {
    string(name: 'COMMIT', defaultValue: '', description: 'The Git commit to be used (empty will checkout the latest commit)')
  }
  stages {
    stage('Filter build') {
      options { skipDefaultCheckout() }
      agent { label 'ubuntu-20 && immutable' }
      when {
        beforeAgent true
        anyOf {
          triggeredBy cause: "IssueCommentCause"
          expression {
            def ret = isUserTrigger() || isUpstreamTrigger()
            if(!ret){
              currentBuild.result = 'NOT_BUILT'
              currentBuild.description = "The build has been skipped"
              currentBuild.displayName = "#${BUILD_NUMBER}-(Skipped)"
              echo("the build has been skipped due the trigger is a branch scan and the allowed ones are manual, GitHub comment, and upstream job")
            }
            return ret
          }
        }
      }
      environment {
        PATH = "${env.PATH}:${env.WORKSPACE}/bin"
        HOME = "${env.WORKSPACE}"
      }
      stages {
        stage('Checkout') {
          options { skipDefaultCheckout() }
          steps {
            pipelineManager([ cancelPreviousRunningBuilds: [ when: 'PR' ] ])
            deleteDir()
            smartGitCheckout()
            stash(allowEmpty: true, name: 'source', useDefaultExcludes: false)
            setEnvVar('IS_BRANCH_AVAILABLE', isBranchUnifiedReleaseAvailable(env.BRANCH_NAME))
            dir("${BASE_DIR}") {
              setEnvVar('VERSION', sh(label: 'Get version', script: 'make get-version', returnStdout: true)?.trim())
            }
          }
        }
        stage('Package') {
          options { skipDefaultCheckout() }
          matrix {
            agent {
              label "${PLATFORM}"
            }
            axes {
              axis {
                name 'PLATFORM'
                values 'ubuntu-20 && immutable', 'arm'
              }
              axis {
                name 'TYPE'
                values 'snapshot', 'staging'
              }
            }
            stages {
              stage('Package') {
                options { skipDefaultCheckout() }
                environment {
                  PLATFORMS = "${isArm() ? 'linux/arm64' : ''}"
                  PACKAGES = "${isArm() ? 'docker' : ''}"
                }
                steps {
                  runIfNoMainAndNoStaging() {
                    runPackage(type: env.TYPE)
                  }
                }
              }
              stage('Publish') {
                options { skipDefaultCheckout() }
                steps {
                  runIfNoMainAndNoStaging() {
                    publishArtifacts(type: env.TYPE)
                  }
                }
              }
            }
          }
          post {
            failure {
              notifyStatus(subject: "[${env.REPO}@${env.BRANCH_NAME}] package failed.",
                           body: 'Contact the Productivity team [#observablt-robots] if you need further assistance.')
            }
          }
        }
        stage('DRA Snapshot') {
          options { skipDefaultCheckout() }
          // The Unified Release process keeps moving branches as soon as a new
          // minor version is created, therefore old release branches won't be able
          // to use the release manager as their definition is removed.
          when {
            expression { return env.IS_BRANCH_AVAILABLE == "true" }
          }
          steps {
            runReleaseManager(type: 'snapshot', outputFile: env.DRA_OUTPUT)
          }
          post {
            failure {
              notifyStatus(analyse: true,
                           file: "${BASE_DIR}/${env.DRA_OUTPUT}",
                           subject: "[${env.REPO}@${env.BRANCH_NAME}] The Daily releasable artifact failed.",
                           body: 'Contact the Release Platform team [#platform-release].')
            }
          }
        }
        stage('DRA Staging (if no main)') {
          options { skipDefaultCheckout() }
          when {
            allOf {
              // The Unified Release process keeps moving branches as soon as a new
              // minor version is created, therefore old release branches won't be able
              // to use the release manager as their definition is removed.
              expression { return env.IS_BRANCH_AVAILABLE == "true" }
              not { branch 'main' }
            }
          }
          steps {
            runReleaseManager(type: 'staging', outputFile: env.DRA_OUTPUT)
          }
          post {
            failure {
              notifyStatus(analyse: true,
                           file: "${BASE_DIR}/${env.DRA_OUTPUT}",
                           subject: "[${env.REPO}@${env.BRANCH_NAME}] The Daily releasable artifact failed.",
                           body: 'Contact the Release Platform team [#platform-release].')
            }
          }
        }
      }
    }
  }
  post {
    cleanup {
      notifyBuildResult(prComment: false)
    }
  }
}

def runPackage(def args = [:]) {
  def makeGoal = args.type.equals('staging') ? 'release-manager-release' : 'release-manager-snapshot'
  deleteDir()
  unstash 'source'
  dir("${BASE_DIR}"){
    withMageEnv() {
      sh(label: 'make release-manager', script: "make ${makeGoal}")
    }
  }
}

def publishArtifacts(def args = [:]) {
  // Copy those files to another location with the sha commit to test them afterward.
  googleStorageUpload(bucket: getBucketLocation(args.type),
    credentialsId: "${JOB_GCS_CREDENTIALS}",
    pathPrefix: "${BASE_DIR}/build/distributions/",
    pattern: "${BASE_DIR}/build/distributions/**/*",
    sharedPublicly: true,
    showInline: true)
}

def getBucketLocation(type) {
  return "gs://${JOB_GCS_BUCKET}/${getBucketRelativeLocation(type)}"
}

def getBucketRelativeLocation(type) {
  def folder = type.equals('snapshot') ? 'commits' : type
  return "${folder}/${env.GIT_BASE_COMMIT}"
}

def getBucketPathPrefix(type) {
  // JOB_GCS_BUCKET contains the bucket and some folders,
  // let's build up the folder structure without the parent folder
  def relative = getBucketRelativeLocation(type)
  if (JOB_GCS_BUCKET.contains('/')) {
    return JOB_GCS_BUCKET.substring(JOB_GCS_BUCKET.indexOf('/') + 1) + '/' + relative
  }
  return relative
}

def runReleaseManager(def args = [:]) {
  deleteDir()
  unstash 'source'
  googleStorageDownload(bucketUri: "${getBucketLocation(args.type)}/*",
                        credentialsId: "${JOB_GCS_CREDENTIALS}",
                        localDirectory: "${BASE_DIR}/build/distributions",
                        pathPrefix: getBucketPathPrefix(args.type))
  dir("${BASE_DIR}") {
    def makeGoal = args.type.equals('staging') ? 'release-manager-dependencies-release' : 'release-manager-dependencies-snapshot'
    withMageEnv() {
      sh(label: 'create dependencies file', script: "make ${makeGoal}")
    }
    dockerLogin(secret: env.DOCKER_SECRET, registry: env.DOCKER_REGISTRY)
    releaseManager(project: 'fleet-server',
                   version: env.VERSION,
                   type: args.type,
                   artifactsFolder: 'build/distributions',
                   outputFile: args.outputFile)
  }
}

def notifyStatus(def args = [:]) {
  def releaseManagerFile = args.get('file', '')
  def analyse = args.get('analyse', false)
  def subject = args.get('subject', '')
  def body = args.get('body', '')
  releaseManagerNotification(file: releaseManagerFile,
                             analyse: analyse,
                             slackChannel: "${env.SLACK_CHANNEL}",
                             slackColor: 'danger',
                             slackCredentialsId: 'jenkins-slack-integration-token',
                             to: "${env.NOTIFY_TO}",
                             subject: subject,
                             body: "Build: (<${env.RUN_DISPLAY_URL}|here>).\n ${body}")
}

def runIfNoMainAndNoStaging(Closure body) {
  if (env.BRANCH_NAME.equals('main') && env.TYPE == 'staging') {
    echo 'INFO: staging artifacts for the main branch are not required.'
  } else {
    body()
  }
}

def smartGitCheckout() {
  // Checkout the given commit
  if (env.COMMIT?.trim()) {
    gitCheckout(basedir: "${BASE_DIR}",
                branch: "${env.COMMIT}",
                credentialsId: "${JOB_GIT_CREDENTIALS}",
                repo: "https://github.com/elastic/${REPO}.git")
  } else {
    gitCheckout(basedir: "${BASE_DIR}",
                githubNotifyFirstTimeContributor: false,
                shallow: false,
                reference: "/var/lib/jenkins/.git-references/${REPO}.git")
  }
}
